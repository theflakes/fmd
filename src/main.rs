extern crate tree_magic;
extern crate fuzzyhash;
extern crate sha256;
extern crate crypto;
extern crate path_abs;
extern crate dunce;
extern crate chrono;
extern crate goblin;
extern crate entropy;

#[macro_use] extern crate lazy_static;

mod data_defs;
mod ordinals;

use data_defs::*;
use fuzzyhash::FuzzyHash;
use goblin::pe::PE;
use std::path::Path;
use std::ptr::null;
use std::{io, str};
use std::env;
use std::process;
use std::borrow::Cow;
use std::io::{Read, Seek};
use crypto::digest::Digest;
use std::fs::{self, File};
use path_abs::{PathAbs, PathInfo};
use chrono::prelude::{DateTime, Utc};
use std::time::SystemTime;
use goblin::{error, Object};
use entropy::shannon_entropy;
use std::os::windows::prelude::*;


// report out in json
fn print_log(
                timestamp: String,
                path: String,
                bytes: u64,
                mime_type: String, 
                is_hidden: bool,
                timestamps: FileTimestamps,
                entropy: f32,
                md5: String,
                sha1: String,
                sha256: String,
                ssdeep: String,
                binary: Binary,
                pprint: bool,
                strings: Vec<String>
            ) -> io::Result<()> {
    if pprint {
        MetaData::new(
            timestamp,
            DEVICE_TYPE.to_string(),
            path.to_string(),
            bytes,
            mime_type,
            is_hidden,
            timestamps,
            entropy,
            md5, 
            sha1, 
            sha256, 
            ssdeep,
            binary,
            strings
        ).report_pretty_log();
    } else {
        MetaData::new(
            timestamp,
            DEVICE_TYPE.to_string(),
            path.to_string(),
            bytes,
            mime_type, 
            is_hidden,
            timestamps,
            entropy,
            md5, 
            sha1, 
            sha256, 
            ssdeep,
            binary,
            strings
        ).report_log();
    }
    
    Ok(())
}


// get handle to a file
pub fn open_file(file_path: &std::path::Path) -> std::io::Result<std::fs::File> {
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
pub fn read_file_bytes(mut file: &std::fs::File) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    file.rewind(); // need to reset to beginning of file if file has already been read
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}


fn get_sha1(buffer: &Vec<u8>) -> std::io::Result<(String)> {
    let mut hasher = crypto::sha1::Sha1::new();
    hasher.input(buffer);
    let sha1 = hasher.result_str();
    Ok(sha1)
}


// get metadata for the file's content (md5, sha1, ...)
pub fn get_file_content_info(
                                file: &std::fs::File,
                                mut buffer: &Vec<u8>
                            ) -> std::io::Result<(String, String, String)> 
{
    let mut md5 = String::new();
    let mut sha1 = String::new();
    let mut sha256 = String::new();
    md5 = format!("{:x}", md5::compute(buffer)).to_lowercase();
    sha1 = get_sha1(buffer)?;
    sha256 = sha256::digest_bytes(buffer);
    drop(buffer);
    Ok((md5, sha1, sha256))
}


/*
    detects if the binary is a .Net assembly
    .Net assemblies will only have one lib and one function in imports
*/
fn is_dotnet(imps: &Vec<Imports>) -> io::Result<bool> {
    if imps.len() == 1 {
        if imps[0].count ==1 
            && imps[0].lib == "mscoree.dll" 
            && imps[0].name[0] == "_CorExeMain" {
            return Ok(true);
        }
    }
    Ok(false)
}


fn parse_pe_imports(imports: &Vec<goblin::pe::import::Import>) -> io::Result<(Vec<Imports>, bool)> {
    let mut dlls:Vec<&str> = Vec::new();
    let mut imps: Vec<Imports> = Vec::new();
    for i in imports.iter() {
        if dlls.contains(&i.dll) { continue; }
        dlls.push(i.dll);
        let mut temp = Imports::default();
        temp.lib = i.dll.to_string();
        for m in imports.iter() {
            if i.dll != m.dll { continue; }
            temp.count += 1;
            temp.name.push(m.name.to_string());
        }
        imps.push(temp);
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
                        -> io::Result<((String, String, String, String, u32, u32))> {
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
    imphash_text = imphash_text.trim_end_matches(",").to_string();
    let imphash = format!("{:x}", md5::compute(imphash_text.clone())).to_lowercase();
    let (imphash_text_sorted, imphash_sorted) = get_imphash_sorted(&mut imphash_array)?;
    let imphash_bytes: Vec<u8> = imphash_text.as_bytes().to_vec();
    let imphash_bytes_ordered: Vec<u8> = imphash_text_sorted.as_bytes().to_vec();
    let imphash_ssdeep = get_ssdeep_hash(&imphash_bytes)?;
    let imphash_ssdeep_sorted = get_ssdeep_hash(&imphash_bytes_ordered)?;
    
    Ok((
        imphash, imphash_sorted, imphash_ssdeep, 
        imphash_ssdeep_sorted, total_dlls, total_funcs
    ))
}


fn parse_pe_exports(exports: &Vec<goblin::pe::export::Export>) -> io::Result<(Vec<String>, u32)>{
    let mut exps:Vec<String> = Vec::new();
    let mut exports_count = 0;
    for e in exports.iter() {
        exps.push(e.name.unwrap_or("").to_string());
        exports_count += 1;
    }
    Ok((exps, exports_count))
}


fn get_date_string(timestamp: u32) -> io::Result<String> {
    let temp = timestamp as i64;
    let dt = chrono::NaiveDateTime::from_timestamp_opt(temp, 0).unwrap()
        .format("%Y-%m-%dT%H:%M:%S")
        .to_string();
    Ok(dt)
}


pub fn get_strings(buffer: &Vec<u8>, length: usize) -> io::Result<Vec<String>> {
    let mut results: Vec<String> = Vec::new();
    let mut chars: Vec<u8> = Vec::new();
    let ascii = 32..126;
    for b in buffer {
        if ascii.contains(b) {
            chars.push(*b);
        } else {
            if chars.len() >= length {
                results.push(String::from_utf8(chars).unwrap());
            }
            chars = Vec::new();
        }
    }
    Ok(results)
}


fn bin_to_string(bytes: &Vec<u8>) -> io::Result<String> {
    let mut s = String::new();
    if bytes.len() >= 128 {
        s = String::from_utf8_lossy(&bytes[0..127]).into_owned();
    } else {
        s = String::from_utf8_lossy(bytes).into_owned();
    }

    let first_bytes_as_string = s.as_str()
                                        .replace('\u{0000}', ".")
                                        .to_string();
    Ok(first_bytes_as_string)
}


fn get_imports(buffer: &Vec<u8>) -> io::Result<(Binary)> {
    let mut bin = Binary::default();
    match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => {
            println!("elf: {:#?}", &elf);
        },
        Object::PE(pe) => {
            (bin.imports, bin.is_dotnet) = parse_pe_imports(&pe.imports)?;
            (bin.imphash, bin.imphash_sorted, 
                bin.imphash_ssdeep, bin.imphash_ssdeep_sorted,
                bin.imports_lib_count, bin.imports_func_count) = get_imphashes(&pe.imports)?;
            bin.is_64 = pe.is_64;
            bin.is_lib = pe.is_lib;
            (bin.exports, bin.exports_count) = parse_pe_exports(&pe.exports)?;
            bin.original_filename = pe.name.unwrap_or("").to_string();
            bin.timestamps.compile = get_date_string(pe.header.coff_header.time_date_stamp)?;
            bin.timestamps.debug = get_date_string(pe.debug_data.unwrap().image_debug_directory.time_date_stamp)?;
            bin.linker_major_version = pe.header.optional_header.unwrap().standard_fields.major_linker_version;
            bin.linker_minor_version = pe.header.optional_header.unwrap().standard_fields.minor_linker_version;
            bin.first_128_bytes = bin_to_string(&buffer)?;
        },
        Object::Mach(mach) => {
            println!("mach: {:#?}", &mach);
        },
        Object::Archive(archive) => {
            println!("archive: {:#?}", &archive);
        },
        Object::Unknown(magic) => { println!("unknown magic: {:#x}", magic) }
    }
    Ok(bin)
}


fn get_entropy(buffer: &Vec<u8>) -> io::Result<f32> {
    Ok(shannon_entropy(buffer))
}


// find the parent directory of a given dir or file
pub fn get_abs_path(path: &std::path::Path) -> io::Result<(std::path::PathBuf)> {
    let abs = PathAbs::new(&path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}


fn get_time_iso8601() -> io::Result<(String)> {
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();
    Ok(now.to_rfc3339())
}


// get date into the format we need
pub fn format_date(time: DateTime::<Utc>) -> io::Result<String> {
    Ok(time.format("%Y-%m-%dT%H:%M:%S.%3f").to_string())
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
                    strings = arg.as_str().parse::<usize>().unwrap();
                    get_strings_length = false;
                } else {
                    file_path = arg.clone();
                }
            }
        }
    }
    Ok((file_path.clone(), pprint, strings))
}


// is a file or directory hidden
pub fn is_hidden(file_path: &Path) -> io::Result<bool> {
    let metadata = fs::metadata(file_path)?;
    let attributes = metadata.file_attributes();
    
    // see: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
    if (attributes & 0x2) > 0 {
        Ok(true)
    } else {
        Ok(false)
    }
}


fn get_file_times(path: &Path) -> io::Result<FileTimestamps> {
    let mut ftimes = FileTimestamps::default();
    let metadata = match fs::metadata(dunce::simplified(&path)) {
        Ok(m) => m,
        _ => return Ok(ftimes)
    };
    if metadata.created().is_ok() { 
        ftimes.create = format_date(metadata.created()?.to_owned().into())?;
    }
    ftimes.access = format_date(metadata.accessed()?.to_owned().into())?;
    ftimes.modify = format_date(metadata.modified()?.to_owned().into())?;
    Ok(ftimes)
}


fn start_analysis(file_path: String, pprint: bool, strings_length: usize) -> io::Result<()> {
    let mut imps = false;
    let timestamp = get_time_iso8601()?;
    let path = convert_to_path(&file_path)?;
    let ftimes = get_file_times(&path)?;
    let abs_path = get_abs_path(path)?.as_path().to_str().unwrap().to_string();
    let file = open_file(&path)?;
    let mut md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string(); // md5 of empty file
    let mut sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(); // sha1 of empty file
    let mut sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(); // sha256 or empty file
    let mut mime_type = String::new();
    let mut ssdeep = String::new();
    let mut bytes = file.metadata().unwrap().len();
    let mut bin = Binary::default();
    let mut buffer: Vec<u8> = Vec::new();
    let mut entropy: f32 = 0.0;
    let mut strings: Vec<String> = Vec::new();
    let is_hidden = is_hidden(&path)?;
    if bytes > 0 {
        buffer = read_file_bytes(&file)?;
        entropy = shannon_entropy(&buffer);
        ssdeep = get_ssdeep_hash(&buffer)?;
        mime_type = get_mimetype(&buffer)?;
        (md5, sha1, sha256) = get_file_content_info(&file, &buffer)?;
        bin = get_imports(&buffer)?;
        if strings_length > 0 {strings = get_strings(&buffer, strings_length)?;}
    }
    print_log(timestamp, abs_path, bytes, 
                mime_type, is_hidden, ftimes, 
                entropy, md5, sha1, sha256, ssdeep, 
                bin, pprint, strings)?;
                Ok(())
}


fn main() -> io::Result<()> {
    let (file_path, pprint, strings_length) = get_args()?;
    start_analysis(file_path, pprint, strings_length)?;
    Ok(())
}