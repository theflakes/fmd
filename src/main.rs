extern crate tree_magic;
extern crate fuzzyhash;
extern crate sha256;
extern crate crypto;
extern crate path_abs;
extern crate dunce;
extern crate goblin;
extern crate entropy;
extern crate exe;

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
use std::path::Path;
use std::ptr::null;
use std::str::from_utf8;
use std::{io, str};
use std::env;
use std::process;
use std::borrow::Cow;
use crypto::digest::Digest;
use std::fs::{self, File};
use std::io::{BufReader, Read, Seek, Write};
use path_abs::{PathAbs, PathInfo};
use std::time::SystemTime;
use goblin::{error, Object};
use entropy::shannon_entropy;
use std::os::windows::prelude::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};


// report out in json
fn print_log(
                path: String,
                bytes: u64,
                mime_type: String, 
                is_hidden: bool,
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
            bytes,
            mime_type,
            is_hidden,
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
            bytes,
            mime_type, 
            is_hidden,
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


fn convert_to_path(target_file: &str) -> io::Result<&Path> {
    let file_path = Path::new(target_file);
    if file_path.exists() && file_path.is_file() { 
        return Ok(file_path)
    }

    println!("\nFile not found!\n");
    process::exit(1)
}


// read in file as byte vector
fn read_file_bytes(mut file: &File) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    file.rewind(); // need to reset to beginning of file if file has already been read
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}


fn get_sha1(buffer: &Vec<u8>) -> std::io::Result<String> {
    let mut hasher = crypto::sha1::Sha1::new();
    hasher.input(buffer);
    let sha1 = hasher.result_str();
    Ok(sha1)
}


// get metadata for the file's content (md5, sha1, ...)
fn get_file_hashes(buffer: &Vec<u8>) -> std::io::Result<Hashes> {
    let mut hashes = Hashes::default();
    hashes.md5 = format!("{:x}", md5::compute(buffer)).to_lowercase();
    hashes.sha1 = get_sha1(buffer)?;
    hashes.sha256 = sha256::digest_bytes(buffer);
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


fn get_imphash_sorted(imphash_array: &mut Vec<String>) -> io::Result<(String, String)> {
    imphash_array.sort();
    let mut imphash_text_sorted = String::new();
    for i in imphash_array.iter() {
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
                        -> io::Result<(ImpHashes, u32, u32)> {
    let mut imphash_array: Vec<String> = Vec::new();    // store in array for calculating imphash on sorted
    let mut imphash_text = String::new();       // text imphash for imports in bin natural order
    let mut total_dlls = 0;
    let mut total_funcs = 0;
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
        total_funcs += 1;
        track_dll = i.dll.to_string();
    }
    let mut imphashes = ImpHashes::default();
    imphash_text = imphash_text.trim_end_matches(",").to_string();
    imphashes.hash = format!("{:x}", md5::compute(imphash_text.clone())).to_lowercase();
    let mut imphash_text_sorted = String::new();
    (imphash_text_sorted, imphashes.hash_sorted) = get_imphash_sorted(&mut imphash_array)?;
    let imphash_bytes: Vec<u8> = imphash_text.as_bytes().to_vec();
    let imphash_bytes_ordered: Vec<u8> = imphash_text_sorted.as_bytes().to_vec();
    imphashes.ssdeep = get_ssdeep_hash(&imphash_bytes)?;
    imphashes.ssdeep_sorted = get_ssdeep_hash(&imphash_bytes_ordered)?;
    
    Ok((imphashes, total_dlls, total_funcs))
}


fn parse_pe_exports(exports: &Vec<goblin::pe::export::Export>) -> io::Result<Exports> {
    let mut exps = Exports::default();
    for e in exports.iter() {
        exps.names.push(e.name.unwrap_or("").to_string());
        exps.count += 1;
    }
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


/*
    See: https://github.com/frank2/exe-rs/blob/main/src/tests.rs

    The Goblin PE parser doesn't support parsing this PE structure, therefore using exe-rs
    Is not parsing .Net file info
*/
fn get_pe_file_info(file_path: String) -> io::Result<PeFileInfo> {
    let mut file_info = PeFileInfo::default();
    let pefile = match exe::VecPE::from_disk_file(file_path) {
        Ok(p) => p,
        Err(_e) => return Ok(file_info),
    };
    let vs_version_check = match exe::VSVersionInfo::parse(&pefile) {
        Ok(p) => p,
        Err(_e) => return Ok(file_info),
    };
    let vs_version = vs_version_check;
    if let Some(string_file_info) = vs_version.string_file_info {
        let string_map = string_file_info.children[0].string_map();
        if string_map.contains_key("ProductVersion") {
            file_info.product_version = string_map.get("ProductVersion").unwrap().to_string();
        }
        if string_map.contains_key("OriginalFilename") {
            file_info.original_filename = string_map.get("OriginalFilename").unwrap().to_string();
        }
        if string_map.contains_key("FileDescription") {
            file_info.file_description = string_map.get("FileDescription").unwrap().to_string();
        }
        if string_map.contains_key("FileVersion") {
            file_info.file_version = string_map.get("FileVersion").unwrap().to_string();
        }
        if string_map.contains_key("ProductName") {
            file_info.product_name = string_map.get("ProductName").unwrap().to_string();
        }
        if string_map.contains_key("CompanyName") {
            file_info.company_name = string_map.get("CompanyName").unwrap().to_string();
        }
        if string_map.contains_key("InternalName") {
            file_info.internal_name = string_map.get("InternalName").unwrap().to_string();
        }
        if string_map.contains_key("LegalCopyright") {
            file_info.legal_copyright = string_map.get("LegalCopyright").unwrap().to_string();
        }
    }
    Ok(file_info)
}


fn get_sections(pex: &PE) -> io::Result<BinSections>{
    let mut bss = BinSections::default();
    for s in pex.sections.iter() {
        bss.total_sections += 1;
        bss.total_raw_bytes += s.size_of_raw_data;
        bss.total_virt_bytes += s.virtual_size;
        let mut bs: BinSection = BinSection::default();
        bs.name = s.name().unwrap_or("").to_string();
        bs.raw_size = s.size_of_raw_data;
        bs.virt_size = s.virtual_size;
        bss.sections.push(bs);
    }
    Ok(bss)
}


fn get_pe(file_path: String, buffer: &Vec<u8>) -> io::Result<Binary> {
    let mut bin = Binary::default();
    if buffer.len() < 97 { return Ok(bin) } // smallest possible PE size, errors with smaller buffer size
    match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => {
            //println!("Elf binary");
        },
        Object::PE(pex) => {
            (bin.imports, bin.is_dotnet) = parse_pe_imports(&pex.imports)?;
            bin.entry_point = format!("0x{:02x}", pex.entry);
            bin.sections = get_sections(&pex)?;
            (bin.import_hashes, bin.imports.lib_count, bin.imports.func_count) = get_imphashes(&pex.imports)?;
            bin.is_64 = pex.is_64;
            bin.is_lib = pex.is_lib;
            bin.exports = parse_pe_exports(&pex.exports)?;
            bin.pe_info = get_pe_file_info(file_path)?;
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


// find the parent directory of a given dir or file
fn get_abs_path(path: &std::path::Path) -> io::Result<std::path::PathBuf> {
    let abs = PathAbs::new(&path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
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
    let metadata = match fs::metadata(dunce::simplified(&path)) {
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


fn start_analysis(file_path: String, pprint: bool, strings_length: usize) -> io::Result<()> {
    let mut imps = false;
    let mut run_as_admin = false;
    let path = convert_to_path(&file_path)?;
    let abs_path = get_abs_path(path)?.as_path().to_str().unwrap_or("").to_string();
    let mut ftimes = get_file_times(&path)?;
    let mut ads: Vec<DataRun> = Vec::new();
    (ftimes, ads) = get_fname(&abs_path, ftimes).unwrap();
    let file = open_file(&path)?;
    let mut bytes = file.metadata().unwrap().len();
    let is_hidden = is_hidden(&path)?;
    let buffer = read_file_bytes(&file)?;
    let entropy = shannon_entropy(&buffer);
    let mime_type = get_mimetype(&buffer)?;
    let hashes = get_file_hashes(&buffer)?;
    let bin = get_pe(file_path, &buffer)?;
    let mut strings: Vec<String> = Vec::new();
    if strings_length > 0 {strings = get_strings(&buffer, strings_length)?;}
    print_log(abs_path, bytes, mime_type, 
        is_hidden, ftimes.clone(), 
        entropy, hashes, ads, bin, 
        pprint, strings)?;
    Ok(())
}


fn print_help() {
    let help = "
        Author: Brian Kellogg
        License: MIT
        Purpose: Pull various file metadata.
        Usage: fmd [--pretty | -p] ([--strings|-s] #) <file path>
        Options:
            -p, --pretty        Pretty print JSON
            -s, --strings #     Look for strings of length # or longer

        NOTE: Harvesting $FILE_NAME timestamps can only be acquired by running this tool elevated.
              The 'run_as_admin' field shows if the tool was run elevated. If the MFT can be accessed,
              its $STANDARD_INFORMATION dates are preferred.

              Harvesting Alternate Data Stream (ADS) information can only be acquired by running 
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


fn get_args() -> io::Result<(String, bool, usize)> {
    let args: Vec<String> = env::args().collect();
    let mut file_path = String::new();
    let mut pprint = false;
    let mut strings: usize = 0;
    let mut get_strings_length = false;
    if args.len() == 1 { print_help(); }
    for arg in args {
        match arg.as_str() {
            "-p" | "--pretty" => pprint = true,
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
    Ok((file_path.clone(), pprint, strings))
}


fn main() -> io::Result<()> {
    let (file_path, pprint, strings_length) = get_args()?;
    start_analysis(file_path, pprint, strings_length)?;
    Ok(())
}