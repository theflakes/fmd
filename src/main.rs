extern crate tree_magic;
extern crate fuzzyhash;
extern crate crypto;
extern crate path_abs;
extern crate dunce;
extern crate goblin;
extern crate entropy;
extern crate exe;
//extern crate rand;
extern crate lnk;

#[macro_use] extern crate lazy_static;

mod data_defs;
mod ordinals;
mod sector_reader;
mod mft;

use data_defs::*;
use mft::*;
use fuzzyhash::FuzzyHash;
use goblin::pe::PE;
use std::mem::replace;
use std::path::{Path, PathBuf};
use std::ptr::null;
use std::str::from_utf8;
use std::{io, str};
use std::env;
use std::process;
use std::borrow::Cow;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, Write, SeekFrom};
use path_abs::{PathAbs, PathInfo};
use std::time::SystemTime;
use goblin::{error, Object};
use entropy::shannon_entropy;
use std::os::windows::prelude::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use lnk::{ShellLink};
//use rand::distributions::{ChiSquared, IndependentSample, Sample};


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
                strings: Vec<String>
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
            strings
        ).report_pretty_log();
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
            strings
        ).report_log();
    }
    
    Ok(())
}


// get handle to a file
fn open_file(file_path: &std::path::Path) -> std::io::Result<std::fs::File> {
    Ok(File::open(&file_path)?)
}


fn get_mimetype(buffer: &Vec<u8>) -> io::Result<String> {
    let mtype = tree_magic::from_u8(&buffer);
    Ok(mtype)
}


/* 
    See:    https://github.com/rustysec/fuzzyhash-rs
            https://docs.rs/fuzzyhash/latest/fuzzyhash/
*/
fn get_ssdeep_hash(mut buffer: &Vec<u8>) -> io::Result<String> {
    let ssdeep = FuzzyHash::new(buffer);
    Ok(ssdeep.to_string())
}


// read in file as byte vector
fn read_file_bytes(mut file: &File) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    file.rewind(); // need to reset to beginning of file if file has already been read
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}


fn get_md5(buffer: &Vec<u8>) -> io::Result<String> {
    Ok(format!("{:x}", md5::compute(buffer)).to_lowercase())
}


fn get_sha1(buffer: &Vec<u8>) -> io::Result<String> {
    let mut hasher = crypto::sha1::Sha1::new();
    hasher.input(buffer);
    Ok(hasher.result_str())
}


fn get_sha256(buffer: &Vec<u8>) -> io::Result<String> {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input(buffer);
    Ok(hasher.result_str())
}


// get metadata for the file's content (md5, sha1, ...)
fn get_file_hashes(buffer: &Vec<u8>) -> io::Result<Hashes> {
    let mut hashes = Hashes::default();
    hashes.md5 = get_md5(buffer)?;
    hashes.sha1 = get_sha1(buffer)?;
    hashes.sha256 = get_sha256(buffer)?;
    hashes.ssdeep = get_ssdeep_hash(&buffer)?;
    drop(buffer);
    Ok(hashes)
}


/*
    detects if the binary is a .Net assembly
    .Net assemblies will only have one lib and one function in imports
*/
fn is_dotnet(imps: &Imports) -> io::Result<bool> {
    if imps.imports.len() == 1 {
        if imps.imports[0].count ==1 
            && imps.imports[0].lib == "mscoree.dll" 
            && imps.imports[0].names[0] == "_CorExeMain" {
            return Ok(true);
        }
    }
    Ok(false)
}


fn parse_pe_imports(imports: &Vec<goblin::pe::import::Import>) -> io::Result<(Imports, bool)> {
    let mut dlls:Vec<&str> = Vec::new();
    let mut imps: Imports = Imports::default();
    for i in imports.iter() {
        if dlls.contains(&i.dll) { continue; }
        dlls.push(i.dll);
        let mut temp = Import::default();
        temp.lib = i.dll.to_string();
        for m in imports.iter() {
            if i.dll != m.dll { continue; }
            temp.count += 1;
            temp.names.push(m.name.to_string());
        }
        imps.imports.push(temp);
    }
    let is_dot_net = is_dotnet(&imps)?;
    Ok((imps, is_dot_net))
}


fn get_hash_sorted(hash_array: &mut Vec<String>) -> io::Result<(String, String)> {
    hash_array.sort();
    let mut imphash_text_sorted = String::new();
    for i in hash_array.iter() {
        imphash_text_sorted.push_str(i);
    }
    imphash_text_sorted = imphash_text_sorted.trim_end_matches(",").to_string();
    let imphash_sorted = format!("{:x}", md5::compute(&imphash_text_sorted)).to_lowercase();

    Ok((imphash_text_sorted, imphash_sorted))
}


fn check_ordinal(dll: &str, func: &str) -> io::Result<String> {
    let mut f: String = func.to_ascii_lowercase().replace("ordinal ", "");
    if f.parse::<u32>().is_ok() {
        let o = f.parse::<u32>().unwrap();
        f = ordinals::imphash_resolve(dll, o).to_ascii_lowercase();
    }
    Ok(f)
}


fn get_imphashes(imports: &Vec<goblin::pe::import::Import>) 
                        -> io::Result<(ImpHashes, usize, usize)> {
    let mut imphash_array: Vec<String> = Vec::new();    // store in array for calculating imphash on sorted
    let mut imphash_text = String::new();       // text imphash for imports in bin natural order
    let mut total_dlls = 0;     // dlls imports are in the form of {"dll_name","function_name"} - one to one relationship
    let mut track_dll = String::new();
    for i in imports.iter() {
        let mut temp = String::new();
        if i.dll != track_dll { total_dlls += 1; }
        let mut dll = i.dll.to_ascii_lowercase()
            .replace(".dll", "")
            .replace(".sys", "")
            .replace(".drv", "")
            .replace(".ocx", "").to_string();
        temp.push_str(&dll);
        temp.push_str(".");
        let func = check_ordinal(i.dll, &i.name)?;
        temp.push_str(&func);
        temp.push_str(",");
        imphash_text.push_str(&temp.to_string());
        imphash_array.push(temp.to_string());
        track_dll = i.dll.to_string();
    }
    let mut imphashes = ImpHashes::default();
    imphash_text = imphash_text.trim_end_matches(",").to_string();
    imphashes.md5 = format!("{:x}", md5::compute(imphash_text.clone())).to_lowercase();
    let mut imphash_text_sorted = String::new();
    (imphash_text_sorted, imphashes.md5_sorted) = get_hash_sorted(&mut imphash_array)?;
    let imphash_bytes: Vec<u8> = imphash_text.as_bytes().to_vec();
    let imphash_bytes_ordered: Vec<u8> = imphash_text_sorted.as_bytes().to_vec();
    imphashes.ssdeep = get_ssdeep_hash(&imphash_bytes)?;
    imphashes.ssdeep_sorted = get_ssdeep_hash(&imphash_bytes_ordered)?;
    Ok((imphashes, total_dlls, imports.len()))
}


fn parse_pe_exports(exports: &Vec<goblin::pe::export::Export>) -> io::Result<Exports> {
    let mut exps = Exports::default();
    //let mut exphash_array: Vec<String> = Vec::new();
    let mut exphash_text = String::new();
    for e in exports.iter() {
        exps.names.push(e.name.unwrap_or("").to_string());
        let mut temp = String::new();
        temp.push_str(&e.name.unwrap_or("").to_string());
        temp.push_str(",");
        //exphash_array.push(temp.to_string());
        exphash_text.push_str(&temp.to_string());
    }
    exps.count = exports.len();
    let mut exphashes = ExpHashes::default();
    exphash_text = exphash_text.trim_end_matches(",").to_string();
    exphashes.md5 = format!("{:x}", md5::compute(exphash_text.clone())).to_lowercase();
    //let mut exphash_text_sorted = String::new();
    //(exphash_text_sorted, exphashes.md5_sorted) = get_hash_sorted(&mut exphash_array)?;
    let exphash_bytes: Vec<u8> = exphash_text.as_bytes().to_vec();
    //let exphash_bytes_ordered: Vec<u8> = exphash_text_sorted.as_bytes().to_vec();
    exphashes.ssdeep = get_ssdeep_hash(&exphash_bytes)?;
    //exphashes.ssdeep_sorted = get_ssdeep_hash(&exphash_bytes_ordered)?;
    exps.hashes = exphashes;
    Ok(exps)
}


fn get_date_string(timestamp: i64) -> io::Result<String> {
    let dt = match chrono::NaiveDateTime::from_timestamp_opt(timestamp, 0) {
            Some(s) => s.format("%Y-%m-%dT%H:%M:%S").to_string(),
            None => "".to_string()
        };
    Ok(dt)
}


fn get_strings(buffer: &Vec<u8>, length: usize) -> io::Result<Vec<String>> {
    let mut results: Vec<String> = Vec::new();
    let mut chars: Vec<u8> = Vec::new();
    let ascii = 32..126;
    for b in buffer {
        if ascii.contains(b) {
            chars.push(*b);
        } else {
            if chars.len() >= length {
                results.push(match String::from_utf8(chars){
                    Ok(s) => s,
                    Err(_e) => "".to_string(),
                });
            }
            chars = Vec::new();
        }
    }
    Ok(results)
}


fn get_hashmap_value(
                    string_map: &HashMap<String, String>, 
                    value_name: &str
                    ) -> io::Result<String> 
{
    let _v = match string_map.get(value_name) {
        Some(v) => return Ok(v.to_string()),
        None => return Ok("".to_string())
    };
}


/*
    See: https://github.com/frank2/exe-rs/blob/main/src/tests.rs

    The Goblin PE parser doesn't support parsing this PE structure, therefore using exe-rs
    Is not parsing .Net file info
*/
fn get_pe_file_info(path: &Path) -> io::Result<PeFileInfo> {
    let mut file_info = PeFileInfo::default();
    let Ok(pefile) = exe::VecPE::from_disk_file(path) else { return Ok(file_info) };
    let Ok(vs_version_check) = exe::VSVersionInfo::parse(&pefile) else { return Ok(file_info) };
    let vs_version = vs_version_check;
    if let Some(string_file_info) = vs_version.string_file_info {
        let Ok(string_map) = string_file_info.children[0].string_map() else { return Ok(file_info) };
        file_info.product_version = get_hashmap_value(&string_map, "ProductVersion")?;
        file_info.original_filename = get_hashmap_value(&string_map, "ProductVersion")?;
        file_info.file_description = get_hashmap_value(&string_map, "FileDescription")?;
        file_info.file_version = get_hashmap_value(&string_map, "FileVersion")?;
        file_info.product_name = get_hashmap_value(&string_map, "ProductName")?;
        file_info.company_name = get_hashmap_value(&string_map, "CompanyName")?;
        file_info.internal_name = get_hashmap_value(&string_map, "InternalName")?;
        file_info.legal_copyright = get_hashmap_value(&string_map, "LegalCopyright")?;
    }
    Ok(file_info)
}


fn read_section(path: &Path, start: u32, size: u32) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start as u64))?;
    let mut buf = vec![0; size as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}


fn get_sections(pex: &PE, path: &Path) -> io::Result<BinSections>{
    let mut bss = BinSections::default();
    for s in pex.sections.iter() {
        bss.total_sections += 1;
        bss.total_raw_bytes += s.size_of_raw_data;
        bss.total_virt_bytes += s.virtual_size;
        let mut bs: BinSection = BinSection::default();
        bs.name = s.name().unwrap_or("").to_string();
        bs.virt_address = format!("0x{:02x}", s.virtual_address);
        bs.raw_size = s.size_of_raw_data;
        bs.virt_size = s.virtual_size;
        let data = read_section(path, s.pointer_to_raw_data, s.size_of_raw_data)?;
        bs.entropy = get_entropy(&data)?;
        bs.md5 = format!("{:x}", md5::compute(&data)).to_lowercase();
        bs.ssdeep = get_ssdeep_hash(&data)?;
        bss.sections.push(bs);
    }
    Ok(bss)
}


fn get_pe(path: &Path, buffer: &Vec<u8>) -> io::Result<Binary> {
    let mut bin = Binary::default();
    if buffer.len() < 97 { return Ok(bin) } // smallest possible PE size, errors with smaller buffer size
    match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => {
            //println!("Elf binary");
        },
        Object::PE(pex) => {
            (bin.imports, bin.is_dotnet) = parse_pe_imports(&pex.imports)?;
            bin.entry_point = format!("0x{:02x}", pex.entry);
            bin.sections = get_sections(&pex, path)?;
            (bin.imports.hashes, bin.imports.lib_count, bin.imports.func_count) = get_imphashes(&pex.imports)?;
            bin.is_64 = pex.is_64;
            bin.is_lib = pex.is_lib;
            bin.exports = parse_pe_exports(&pex.exports)?;
            bin.pe_info = get_pe_file_info(path)?;
            bin.timestamps.compile = get_date_string(pex.header.coff_header.time_date_stamp as i64)?;
            bin.timestamps.debug = match pex.debug_data {
                Some(d) => get_date_string(d.image_debug_directory.time_date_stamp as i64)?,
                None => "".to_string()};
            bin.linker.major_version = match pex.header.optional_header {
                Some(d) => d.standard_fields.major_linker_version,
                None => 0};
            bin.linker.minor_version = match pex.header.optional_header {
                Some(d) => d.standard_fields.minor_linker_version,
                None => 0};
        },
        Object::Mach(mach) => {
            //println!("Mach binary");
        },
        Object::Archive(archive) => {
            //println!("Archive file");
        },
        Object::Unknown(magic) => {  }
    }
    Ok(bin)
}


fn get_entropy(buffer: &Vec<u8>) -> io::Result<f32> {
    Ok(shannon_entropy(buffer))
}


// get date into the format we need
fn format_date(time: DateTime::<Utc>) -> io::Result<String> {
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3f").to_string())
}


// is a file or directory hidden
fn is_hidden(file_path: &Path) -> io::Result<bool> {
    let metadata = fs::metadata(file_path)?;
    let attributes = metadata.file_attributes();
    
    // see: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
    if (attributes & 0x2) > 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}


fn get_file_times<'a>(path: &Path) -> io::Result<FileTimestamps> {
    let mut ftimes = FileTimestamps::default();
    let metadata = match fs::metadata(&path) {
        Ok(m) => m,
        Err(_e) => return Ok(ftimes)
    };
    if metadata.created().is_ok() { 
        ftimes.create_si = format_date(metadata.created()?.to_owned().into())?;
    }
    ftimes.access_si = format_date(metadata.accessed()?.to_owned().into())?;
    ftimes.modify_si = format_date(metadata.modified()?.to_owned().into())?;
    Ok(ftimes)
}


// find the parent directory of a given dir or file
pub fn get_parent_dir(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(d) => return d,
        None => return path
    };
}

// return the path that a symlink points to
fn resolve_link(
        link_path: &std::path::Path,
        file_path: &std::path::Path
    ) -> std::io::Result<std::path::PathBuf> 
{
    let parent_dir = get_parent_dir(link_path);
    match std::env::set_current_dir(parent_dir) {
        Ok(f) => f,
        Err(_e) => return Ok(std::path::PathBuf::new())
    };
    let abs = PathAbs::new(&file_path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}

fn format_hotkey_text(hotkey: String) ->  std::io::Result<String> {
    let mk = hotkey
        .replace("HotkeyFlags { low_byte: ", "")
        .replace(", high_byte: ", " ")
        .replace(" }", "");
    let keys: Vec<&str> = mk.split(' ').collect();
    let mut hk = match keys.len() {
        0 => String::new(),
        n => keys[n-1].to_string()
    };
    for k in keys.iter().rev().skip(1) {
        hk = format!("{}-{}", hk, k);
    }
    Ok(hk)
}

// convert a string to a Rust file path
pub fn push_file_path(
        path: &str, 
        suffix: &str
    ) -> std::path::PathBuf 
{
    let mut p = path.to_owned();
    p.push_str(suffix);
    let r = std::path::Path::new(&p);
    return r.to_owned()
}

/*
    determine if a file is a symlink or not
*/
pub fn get_link_info(link_path: &Path) -> std::io::Result<(Link, bool)> {
    let mut link = Link::default();
    let symlink= match ShellLink::open(link_path) {
        Ok(l) => l,
        Err(_e) => return Ok((link, false))
    };
    let file_path = match symlink.relative_path() {
        Some(p) => push_file_path(p, ""),
        None => std::path::PathBuf::new()
    };
    link.target = resolve_link(&link_path, &file_path)?.as_os_str().to_string_lossy().to_string();
    link.arguments =  match symlink.arguments() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    link.working_dir = match symlink.working_dir() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    link.icon_location = match symlink.icon_location() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    link.hotkey = format_hotkey_text(format!("{:?}", symlink.header().hotkey()))?;
    link.comment = match symlink.name() {
        Some(a) => a.to_string(),
        None => String::new()
    };
    link.show_command = format!("{:?}", symlink.header().show_command());
    link.flags = format!("{:?}", symlink.header().link_flags());
    Ok((link, true))
}


fn get_dir_fname_ext(path: &Path) -> io::Result<(String, String, String)> {
    let dir = match path.parent() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new()
    };;
    let fname = match path.file_name() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new()
    };;
    let ext = match path.extension() {
        Some(a) => a.to_string_lossy().into_owned(),
        None => String::new()
    };
    Ok((dir, fname, ext))
}


fn analyze_file(path: &Path, pprint: bool, strings_length: usize) -> io::Result<()> {
    let p = path.to_string_lossy().into_owned();
    let (dir, fname, ext) = get_dir_fname_ext(path)?;
    let mut ftimes = get_file_times(&path)?;
    let mut ads: Vec<DataRun> = Vec::new();
    let mut link = Link::default();
    let mut is_link = false;
    (link, is_link) = get_link_info(path)?;
    (ftimes, ads) = get_fname(path, ftimes).unwrap();
    let file = open_file(&path)?;
    let mut bytes = file.metadata().unwrap().len();
    let is_hidden = is_hidden(&path)?;
    let buffer = read_file_bytes(&file)?;
    let entropy = shannon_entropy(&buffer);
    let mime_type = get_mimetype(&buffer)?;
    let hashes = get_file_hashes(&buffer)?;
    let bin = get_pe(path, &buffer)?;
    let mut strings: Vec<String> = Vec::new();
    if strings_length > 0 {strings = get_strings(&buffer, strings_length)?;}
    print_log(p, dir, fname, ext,
        bytes, mime_type, is_hidden,  is_link, link, ftimes.clone(), 
        entropy, hashes, ads, bin, pprint, strings)?;
    Ok(())
}


fn is_file_or_dir(path: &Path, pprint: bool, recurse: bool, strings_length: usize) -> io::Result<()> {
    if path.is_file() {
        match analyze_file(path, pprint, strings_length) {
            Ok(a) => a,
            Err(_e) => return Ok(())
        };
    } else if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = match entry {
                Ok(m) => m,
                Err(_e) => continue
            };
            let p = entry.path();
            if p.is_dir() {
                if !recurse { continue; }
                match is_file_or_dir(p.as_path(), pprint, recurse, strings_length) {
                    Ok(a) => a,
                    Err(_e) => continue
                };
            }
            if p.is_file() {
                match analyze_file(p.as_path(), pprint, strings_length) {
                    Ok(a )=> a,
                    Err(_e) => continue
                };
            }
        }
    }

    Ok(())
}


// get the absolute path if given a relative path
fn get_abs_path(path: &Path) -> io::Result<std::path::PathBuf> {
    let abs = PathAbs::new(&path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}


fn convert_to_path(target: &str) -> io::Result<PathBuf> {
    let path = Path::new(target);
    if !path.exists() {
        println!("\nNot found!\n");
        process::exit(1)
    }
    return Ok(get_abs_path(path)?)
}


fn get_args() -> io::Result<(String, bool, bool, usize)> {
    let args: Vec<String> = env::args().collect();
    let mut file_path = String::new();
    let mut pprint = false;
    let mut recurse = false;
    let mut strings: usize = 0;
    let mut get_strings_length = false;
    if args.len() == 1 { print_help(); }
    for arg in args {
        match arg.as_str() {
            "-p" | "--pretty" => pprint = true,
            "-r" | "--recurse" => recurse = true,
            "-s" | "--strings" => get_strings_length = true,
            _ => {
                if get_strings_length {
                    strings = arg.as_str().parse::<usize>().unwrap_or(50);
                    get_strings_length = false;
                } else {
                    file_path = arg.clone();
                }
            }
        }
    }
    Ok((file_path.clone(), pprint, recurse, strings))
}


fn main() -> io::Result<()> {
    let (file_path, pprint, recurse, strings_length) = get_args()?;
    is_file_or_dir(
        convert_to_path(&file_path)?.as_path(), pprint, recurse, strings_length
    )?;
    Ok(())
}


fn print_help() {
    let help = "
        Author: Brian Kellogg
        License: MIT
        Purpose: Pull various file metadata.
        Usage: fmd [--pretty | -p] ([--strings|-s] #) <file path> [--recurse | -r]
        Options:
            -p, --pretty        Pretty print JSON
            -r, --recurse       If passed a directory, recurse into all subdirectories
            -s, --strings #     Look for strings of length # or longer

        NOTE: If passed a directory, all files in that directory will be analyzed.
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