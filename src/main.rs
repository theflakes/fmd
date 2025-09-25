extern crate dunce;
extern crate entropy;
extern crate exe;
extern crate fuzzyhash;
extern crate goblin;
extern crate infer;
extern crate lnk;
extern crate path_abs;
extern crate sha1;
extern crate sha2;

#[macro_use]
extern crate lazy_static;

mod data_defs;
mod elf;
mod macho;
mod mft;
mod ordinals;
mod pe;
mod sector_reader;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use data_defs::*;
use entropy::shannon_entropy;
use fuzzyhash::FuzzyHash;
use goblin::Object;
use lnk::encoding::WINDOWS_1252;
use lnk::extradata::ExtraDataBlock;
use lnk::ShellLink;
use mft::*;
use path_abs::{PathAbs, PathInfo};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};
use std::process;
use std::{io, str};

// report out in json
fn print_log(
    path: String,
    directory: String,
    filename: String,
    extension: String,
    bytes: u64,
    mime_type: String,
    is_hidden: bool,
    is_link: bool,
    link: Link,
    timestamps: FileTimestamps,
    entropy: f32,
    hashes: Hashes,
    ads: Vec<DataRun>,
    binary: Binary,
    pprint: bool,
    strings: Vec<String>,
) -> io::Result<()> {
    let runtime_env = RunTimeEnv::default();
    if pprint {
        MetaData::new(
            runtime_env,
            path.to_string(),
            directory,
            filename,
            extension,
            bytes,
            mime_type,
            is_hidden,
            is_link,
            link,
            timestamps,
            entropy,
            hashes,
            ads,
            binary,
            strings,
        )
        .report_pretty_log();
    } else {
        MetaData::new(
            runtime_env,
            path.to_string(),
            directory,
            filename,
            extension,
            bytes,
            mime_type,
            is_hidden,
            is_link,
            link,
            timestamps,
            entropy,
            hashes,
            ads,
            binary,
            strings,
        )
        .report_log();
    }

    Ok(())
}

// get handle to a file
pub fn open_file(file_path: &std::path::Path) -> std::io::Result<std::fs::File> {
    File::options().read(true).write(false).open(&file_path)
}

fn get_mimetype(buffer: &[u8]) -> Result<String> {
    let kind = infer::get(buffer);
    match kind {
        Some(k) => Ok(k.mime_type().to_string()),
        None => Ok("".to_string()),
    }
}

/*
    See:    https://github.com/rustysec/fuzzyhash-rs
            https://docs.rs/fuzzyhash/latest/fuzzyhash/
*/
fn get_ssdeep_hash(buffer: &Vec<u8>) -> Result<String> {
    let ssdeep = FuzzyHash::new(buffer);
    Ok(ssdeep.to_string())
}

// read in file as byte vector
fn read_file_bytes(mut file: &File) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let _ = file.rewind(); // need to reset to beginning of file if file has already been read
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn get_md5(buffer: &Vec<u8>) -> Result<String> {
    Ok(format!("{:x}", md5::compute(buffer)).to_lowercase())
}

fn get_sha1(buffer: &Vec<u8>) -> Result<String> {
    let mut hasher = Sha1::new();
    hasher.update(buffer);
    Ok(format!("{:x}", hasher.finalize()))
}

fn get_sha256(buffer: &Vec<u8>) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    Ok(format!("{:x}", hasher.finalize()))
}

// get metadata for the file's content (md5, sha1, ...)
fn get_file_hashes(buffer: &Vec<u8>) -> Result<Hashes> {
    let mut hashes = Hashes::default();
    hashes.md5 = get_md5(buffer)?;
    hashes.sha1 = get_sha1(buffer)?;
    hashes.sha256 = get_sha256(buffer)?;
    hashes.ssdeep = get_ssdeep_hash(&buffer)?;
    Ok(hashes)
}

fn get_strings(buffer: &Vec<u8>, length: usize) -> Result<Vec<String>> {
    let mut results: Vec<String> = Vec::new();
    let mut chars: Vec<u8> = Vec::new();
    let ascii = 32..126;
    for b in buffer {
        if ascii.contains(b) {
            chars.push(*b);
        } else {
            if chars.len() >= length {
                results.push(match String::from_utf8(chars) {
                    Ok(s) => s,
                    Err(_e) => "".to_string(),
                });
            }
            chars = Vec::new();
        }
    }
    Ok(results)
}

fn get_binary(path: &Path, buffer: &Vec<u8>) -> Result<Binary> {
    let mut bin = Binary::default();
    if buffer.len() < 4 {
        return Ok(bin);
    } // ELF magic number is 4 bytes
    let _ = match Object::parse(&buffer) {
        Ok(o) => match o {
            Object::Elf(_elf) => {
                bin = elf::get_elf(&buffer).context("Failed to parse ELF!")?;
            }
            Object::PE(_pex) => {
                bin = pe::get_pe(&buffer, path).context("Failed to parse PE!")?;
            }
            Object::Mach(_macho) => {
                bin = macho::get_macho(&buffer).context("Failed to parse Mach‑O!")?;
            }
            Object::Archive(_archive) => {
                //println!("Archive file");
            }
            Object::Unknown(_magic) => {}
            Object::COFF(_) => todo!(),
            _ => {}
        },
        Err(_e) => return Ok(bin),
    };

    Ok(bin)
}

// fn get_entropy(buffer: &Vec<u8>) -> io::Result<f32> {
//     Ok(shannon_entropy(buffer))
// }

// get date into the format we need
fn format_date(time: DateTime<Utc>) -> Result<String> {
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3f").to_string())
}

// is a file or directory hidden
fn is_hidden(file_path: &Path) -> Result<bool> {
    let metadata = fs::metadata(file_path)?;
    let attributes = metadata.file_attributes();

    // see: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
    if (attributes & 0x2) > 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn get_file_times<'a>(path: &Path) -> Result<FileTimestamps> {
    let mut ftimes = FileTimestamps::default();
    let metadata = match fs::metadata(&path) {
        Ok(m) => m,
        Err(_e) => return Ok(ftimes),
    };
    if metadata.created().is_ok() {
        ftimes.create_si = format_date(metadata.created()?.to_owned().into())?;
    }
    ftimes.access_si = format_date(metadata.accessed()?.to_owned().into())?;
    ftimes.modify_si = format_date(metadata.modified()?.to_owned().into())?;
    Ok(ftimes)
}

fn format_hotkey_text(hotkey: String) -> Result<String> {
    let mk = hotkey
        .replace("HotkeyFlags { low_byte: ", "")
        .replace(", high_byte: ", " ")
        .replace(" }", "");
    let keys: Vec<&str> = mk.split(' ').collect();
    let mut hk = match keys.len() {
        0 => String::new(),
        n => keys[n - 1].to_string(),
    };
    for k in keys.iter().rev().skip(1) {
        hk = format!("{}-{}", hk, k);
    }
    Ok(hk)
}

/*
    determine if a file is a symlink or not
*/
pub fn get_link_info(link_path: &Path) -> Result<(Link, bool)> {
    let mut link = Link::default();
    let symlink = match ShellLink::open(link_path, WINDOWS_1252) {
        Ok(l) => l,
        Err(_e) => return Ok((link, false)),
    };
    link.working_dir = match symlink.string_data().working_dir() {
        Some(a) => a.to_string(),
        None => String::new(),
    };
    link.rel_path = match symlink.string_data().relative_path() {
        Some(p) => p.to_string(),
        None => String::new(),
    };

    let target_path = PathBuf::from(&link.rel_path);
    link.abs_path = get_abs_path(&target_path)?.to_string_lossy().into_owned();
    if link.abs_path.is_empty() {
        for block in symlink.extra_data().blocks() {
            match block {
                ExtraDataBlock::EnvironmentProps(target_id) => {
                    if let Some(unicode_target) = target_id.target_unicode() {
                        link.abs_path = unicode_target.to_string();
                        break;
                    } else {
                        link.abs_path = target_id.target_ansi().to_string();
                        break;
                    }
                }
                _ => continue,
            }
        }
    }

    link.arguments = match symlink.string_data().command_line_arguments() {
        Some(a) => a.to_string(),
        None => String::new(),
    };
    link.icon_location = match symlink.string_data().icon_location() {
        Some(a) => a.to_string(),
        None => String::new(),
    };
    link.hotkey = format_hotkey_text(format!("{:?}", symlink.header().hotkey()))?;
    link.comment = match symlink.string_data().name_string() {
        Some(a) => a.to_string(),
        None => String::new(),
    };
    link.show_command = format!("{:?}", symlink.header().show_command());
    link.flags = format!("{:?}", symlink.header().link_flags());
    // let v = match symlink.link_info().) {
    //     Some(a) => a,
    //     None => &volume
    // };
    // link.drive_type = format!("{:?}", v.drive_type());
    // link.drive_serial_number = format!("{:?}", v.drive_serial_number());
    // link.volume_label = format!("{:?}", v.volume_label());
    Ok((link, true))
}

fn get_dir_fname_ext(path: &Path) -> Result<(String, String, String)> {
    let dir = match path.parent() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new(),
    };
    let fname = match path.file_name() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new(),
    };
    let ext = match path.extension() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new(),
    };
    Ok((dir, fname, ext))
}

fn check_extensions(not_exts: bool, extensions: &Vec<String>, ext: &String) -> bool {
    if extensions.len() == 0 {
        return false;
    }
    match not_exts {
        true => {
            if extensions.contains(&ext) {
                return true;
            } else {
                return false;
            }
        }
        false => {
            if !extensions.contains(&ext) {
                return true;
            } else {
                return false;
            }
        }
    }
}

fn analyze_file(
    path: &Path,
    pprint: bool,
    strings_length: usize,
    max_size: u64,
    extensions: &Vec<String>,
    not_exts: bool,
    int_mtypes: bool,
) -> Result<()> {
    let (dir, fname, ext) = get_dir_fname_ext(path)?;
    if check_extensions(not_exts, extensions, &ext) {
        return Ok(());
    }

    // Get file times first
    let ftimes = get_file_times(&path)?;

    // Get link info and ADS data - using a more robust approach for error handling
    let (link, is_link) = get_link_info(path)?;

    // Try to get MFT analysis results (this might return an error)
    let mut ads: Vec<DataRun> = Vec::new();
    let mut timestamps_for_printing = ftimes.clone();

    if let Ok((fts, mft_ads)) = get_fname(path, ftimes) {
        // Use the returned timestamps and ADS data
        timestamps_for_printing = fts;
        ads = mft_ads; // This properly assigns the ads value
    }

    let file = open_file(&path)?;
    let bytes = file.metadata()?.len();
    let is_hidden = is_hidden(&path)?;
    let mut bin = Binary::default();
    let mut entropy: f32 = 0.0;
    let mut hashes = Hashes::default();
    let mut strings: Vec<String> = Vec::new();
    let mut mime_type = String::new();

    if max_size == 0 || bytes <= max_size {
        let buffer = read_file_bytes(&file)?;
        mime_type = get_mimetype(&buffer)?;
        if int_mtypes && !INTERESTING_MIME_TYPES.contains(&mime_type.as_str()) {
            return Ok(());
        }
        bin = get_binary(path, &buffer)?;
        if strings_length > 0 {
            strings = get_strings(&buffer, strings_length)?;
        }
        entropy = shannon_entropy(&buffer);
        hashes = get_file_hashes(&buffer)?;
    }

    let p = path.to_string_lossy().into_owned();
    print_log(
        p,
        dir,
        fname,
        ext,
        bytes,
        mime_type,
        is_hidden,
        is_link,
        link,
        timestamps_for_printing,
        entropy,
        hashes,
        ads,
        bin,
        pprint,
        strings,
    )?;

    Ok(())
}

fn is_file_or_dir(
    path: &Path,
    pprint: bool,
    depth: usize,
    mut current_depth: usize,
    strings_length: usize,
    max_size: u64,
    extensions: &Vec<String>,
    not_exts: bool,
    int_mtypes: bool,
) -> Result<()> {
    if path.is_file() {
        match analyze_file(
            path,
            pprint,
            strings_length,
            max_size,
            extensions,
            not_exts,
            int_mtypes,
        ) {
            Ok(a) => a,
            Err(_e) => return Ok(()),
        };
    } else if path.is_dir() {
        current_depth += 1;
        for entry in fs::read_dir(path)? {
            let e = match entry {
                Ok(m) => m,
                Err(_e) => continue,
            };
            if e.path().is_dir() && (current_depth < depth || depth == 0) {
                if depth == 0 {
                    continue;
                }
                match is_file_or_dir(
                    e.path().as_path(),
                    pprint,
                    depth,
                    current_depth,
                    strings_length,
                    max_size,
                    extensions,
                    not_exts,
                    int_mtypes,
                ) {
                    Ok(a) => a,
                    Err(_e) => continue,
                };
            }
            if e.path().is_file() {
                match analyze_file(
                    e.path().as_path(),
                    pprint,
                    strings_length,
                    max_size,
                    extensions,
                    not_exts,
                    int_mtypes,
                ) {
                    Ok(a) => a,
                    Err(_e) => continue,
                };
            }
        }
    }
    Ok(())
}

// get the absolute path if given a relative path
fn get_abs_path(path: &Path) -> Result<std::path::PathBuf> {
    if path == Path::new("") {
        return Ok(PathBuf::new());
    }
    let abs = PathAbs::new(&path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}

fn convert_to_path(target: &str) -> Result<PathBuf> {
    let path = Path::new(target);
    if !path.exists() {
        println!("\nNot found!\n");
        process::exit(1)
    }
    return Ok(get_abs_path(path)?);
}

fn main() -> Result<()> {
    let (file_path, pprint, depth, strings_length, max_size, extensions, not_exts, int_mtypes) =
        get_args()?;
    is_file_or_dir(
        convert_to_path(&file_path)?.as_path(),
        pprint,
        depth,
        0,
        strings_length,
        max_size,
        &extensions,
        not_exts,
        int_mtypes,
    )?;
    Ok(())
}

fn get_args() -> Result<(String, bool, usize, usize, u64, Vec<String>, bool, bool)> {
    let args: Vec<String> = env::args().collect();
    let mut file_path = String::new();
    let mut pprint = false;
    let mut get_depth = false;
    let mut strings: usize = 0;
    let mut depth: usize = 0;
    let mut get_size = false;
    let mut max_size: u64 = 0;
    let mut get_strings_length = false;
    let mut get_exts = false;
    let mut exts_vec: Vec<String> = Vec::new();
    let mut not_exts = false;
    let mut int_mtypes = false;
    if args.len() == 1 {
        print_help();
    }
    for arg in args {
        match arg.as_str() {
            "-d" | "--depth" => get_depth = true,
            "-e" | "--extensions" => get_exts = true,
            "-h" | "--help" => print_help(),
            "-i" | "--int_mtypes" => int_mtypes = true,
            "-m" | "--maxsize" => get_size = true,
            "-p" | "--pretty" => pprint = true,
            "-s" | "--strings" => get_strings_length = true,
            _ => {
                if get_depth {
                    depth = arg.as_str().parse::<usize>().unwrap_or(0);
                    if depth < 1 {
                        print_help();
                    }
                    get_depth = false;
                } else if get_size {
                    max_size = arg.as_str().parse::<u64>().unwrap_or(0);
                    if max_size < 1 {
                        print_help();
                    }
                    get_size = false;
                } else if get_strings_length {
                    strings = arg.as_str().parse::<usize>().unwrap_or(50);
                    if strings < 1 {
                        print_help();
                    }
                    get_strings_length = false;
                } else if get_exts {
                    let exts = arg.as_str();
                    if exts.starts_with("not:") {
                        not_exts = true
                    }
                    exts_vec = exts
                        .replace(" ", "")
                        .replace("not:", "")
                        .split(',')
                        .map(str::to_string)
                        .collect();
                    get_exts = false;
                } else {
                    file_path = arg.clone();
                }
            }
        }
    }
    Ok((
        file_path.clone(),
        pprint,
        depth,
        strings,
        max_size,
        exts_vec,
        not_exts,
        int_mtypes,
    ))
}

fn print_help() {
    let help = "
Authors: Brian Kellogg
         Jason Langston
License: MIT
Purpose: Pull various file metadata.

Usage:
    fmd [--pretty | -p] ([--strings|-s] #) <file path> ([--depth | -d] #)
    fmd --pretty --depth 3 --extensions 'exe,dll,pif,ps1,bat,com'
    fmd --pretty --depth 3 --extensions 'not:exe,dll,pif,ps1,bat,com'
        This will process all files that do not have the specified extensions.

Options:
    -d, --depth #       If passed a directory, recurse into all subdirectories
                        to the specified subdirectory depth
    -e, --extensions *  Quoted list of comma seperated extensions
                        - Any extensions not in the list will be ignored
    -h, --help          Show this help message
    -i, --int_mtypes    Only analyze files that are more interesting mime types
    -m, --maxsize #     Max file size in bytes to perform content analysis on
                        - Any file larger than this will not have the following run:
                          hashing, entropy, mime type, strings, PE analysis
    -p, --pretty        Pretty print JSON
    -s, --strings #     Look for strings of length # or longer

If just passed a directory, only the contents of that directory will be processed.
    - i.e. no subdirectories will be processed.

fmd.exe <directory> --depth 1
    - This will work exactly as if the '--depth' 1 option was not specified.

Mimetypes are determined by examining a file's contents.
    - Interesting mime types:
        application/vnd.android.package-archive
        application/vnd.microsoft.portable-executable
        application/vnd.openxmlformats-officedocument.presentationml.presentation
        application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
        application/vnd.openxmlformats-officedocument.wordprocessingml.document
        application/x-binary
        application/x-csh
        application/x-debian-package
        application/x-dosexec
        application/x-dynamic-link-library
        application/x-executable
        application/x-gtar
        application/x-java-archive
        application/x-jar
        application/x-macbinary
        application/x-mac-package
        application/x-mach-o
        application/x-mach-binary
        application/x-ms-application
        application/x-ms-dos-executable
        application/x-ms-download
        application/x-ms-wizard
        application/x-pkcs12
        application/x-pkcs7-cert
        application/x-rpm
        application/x-shellscript
        application/x-tar
        application/x-elf
        application/x-sharedlib
        application/x-mac-package
        application/x-nuscript
        application/x-nushell
        application/wasm
        application/hta
        application/mac-binary
        application/macbinary
        application/octet-stream
        text/javascript
        text/x-shellscript
        text/x-nushell

NOTE:
    If passed a directory, all files in that directory will be analyzed.
    Harvesting $FILE_NAME timestamps can only be done by running this tool elevated.
    The 'run_as_admin' field shows if the tool was run elevated.

    Harvesting Alternate Data Stream (ADS) information can only be done by running
    this tool elevated. ADS information is acquired by directly accessing the NTFS which
    requires elevation.

    'runtime_env' stores information on the device that this tool was run on.

    PE Sections:
    - 'total_sections' reports how many PE sections are found after the PE headers.
    - 'total_raw_bytes' cumulative size in bytes of all raw, on disk, sections.
    - 'total_virt_bytes' cumulative size in bytes of all virtual, in memory, sections.
    - if 'total_virt_bytes' is much larger than 'total_raw_bytes', this can indicate
      a packed binary.

    Certain forensic information can only be harvested when the file is analyzed on
    the filesystem of origin.
    - e.g. timestamps and alternate data streams are lost when the file is moved
      off of the filesystem of origin.
    ";
    println!("{}", help);
    process::exit(1)
}
