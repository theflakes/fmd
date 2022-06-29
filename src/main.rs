extern crate tree_magic;
extern crate fuzzyhash;
extern crate sha256;
extern crate crypto;
extern crate path_abs;
extern crate dunce;
extern crate chrono;
extern crate goblin;

#[macro_use] extern crate lazy_static;

mod data_defs;

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


// report out in json
fn print_log(
                timestamp: String,
                path: String,
                bytes: u64,
                mime_type: String, 
                md5: String,
                sha1: String,
                sha256: String,
                ssdeep: String,
                binary: Binary,
                pprint: bool
            ) -> io::Result<()> {
    if pprint {
        MetaData::new(
            timestamp,
            DEVICE_TYPE.to_string(),
            path.to_string(),
            bytes,
            mime_type, 
            md5, 
            sha1, 
            sha256, 
            ssdeep,
            binary
        ).report_pretty_log();
    } else {
        MetaData::new(
            timestamp,
            DEVICE_TYPE.to_string(),
            path.to_string(),
            bytes,
            mime_type, 
            md5, 
            sha1, 
            sha256, 
            ssdeep,
            binary
        ).report_log();
    }
    
    Ok(())
}


// get handle to a file
pub fn open_file(
                    file_path: &std::path::Path
                ) -> std::io::Result<std::fs::File> 
{
    Ok(File::open(&file_path)?)
}


fn get_mimetype(target_file: &Path) -> io::Result<String> {
    let mtype = tree_magic::from_filepath(target_file);

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
pub fn read_file_bytes(
                        mut file: &std::fs::File
                    ) -> std::io::Result<Vec<u8>> 
{
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
                            ) -> std::io::Result<(u64, String, String, String)> 
{
    let mut md5 = String::new();
    let mut sha1 = String::new();
    let mut sha256 = String::new();
    let bytes = file.metadata()?.len();
    if bytes != 0 { // don't bother with opening empty files
        md5 = format!("{:x}", md5::compute(buffer)).to_lowercase();
        sha1 = get_sha1(buffer)?;
        sha256 = sha256::digest_bytes(buffer);
        drop(buffer);
    } else {
        md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string(); // md5 of empty file
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(); // sha1 of empty file
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(); // sha256 or empty file
    }
    Ok((bytes, md5, sha1, sha256))
}


fn init_imports_struct() -> Imports {
    let imps: Vec<String> = Vec::new();
    let mut imports = Imports {
        dll: String::new(),
        count: 0,
        name: imps
    };
    return imports
}


fn init_bin_struct() -> Binary {
    let imps: Vec<Imports> = Vec::new();
    let exps: Vec<String> = Vec::new();
    let mut bin = Binary {
        is_64: false,
        is_lib: false,
        original_filename: String::new(),
        imphash: String::new(),
        imphash_sorted: String::new(),
        imphash_ssdeep: String::new(),
        imphash_ssdeep_sorted: String::new(),
        imports_lib_count: 0,
        imports_func_count: 0,
        imports: imps,
        exports_count: 0,
        exports: exps
    };
    return bin
}


fn parse_pe_imports(imports: &Vec<goblin::pe::import::Import>) -> io::Result<Vec<Imports>> {
    let mut dlls:Vec<&str> = Vec::new();
    let mut imps: Vec<Imports> = Vec::new();
    for i in imports.iter() {
        if dlls.contains(&i.dll) { continue; }
        dlls.push(i.dll);
        let mut temp = init_imports_struct();
        temp.dll = i.dll.to_string();
        for m in imports.iter() {
            if i.dll != m.dll { continue; }
            temp.count += 1;
            temp.name.push(m.name.to_string());
        }
        imps.push(temp.clone());
    }
    Ok(imps)
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
        let dll = i.dll.to_ascii_lowercase()
            .replace(".dll", "")
            .replace(".sys", "")
            .replace(".drv", "")
            .replace(".ocx", "").to_string();
        temp.push_str(&dll);
        temp.push_str(".");
        temp.push_str(&i.name
            .to_string().to_ascii_lowercase()
            .replace("ordinal ", ""));
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


fn get_imports(path: &Path) -> io::Result<(Binary)> {
    let buffer = fs::read(path)?;
    let mut bin = init_bin_struct();
    match Object::parse(&buffer).unwrap() {
        Object::Elf(elf) => {
            println!("elf: {:#?}", &elf);
        },
        Object::PE(pe) => {
            bin.imports = parse_pe_imports(&pe.imports)?;
            (bin.imphash, bin.imphash_sorted, 
                bin.imphash_ssdeep, bin.imphash_ssdeep_sorted,
                bin.imports_lib_count, bin.imports_func_count) = get_imphashes(&pe.imports)?;
            bin.is_64 = pe.is_64;
            bin.is_lib = pe.is_lib;
            (bin.exports, bin.exports_count) = parse_pe_exports(&pe.exports)?;
            bin.original_filename = pe.name.unwrap_or("").to_string();
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


// find the parent directory of a given dir or file
pub fn get_abs_path(
                path: &std::path::Path
            ) -> io::Result<(std::path::PathBuf)> 
{
    let abs = PathAbs::new(&path)?;
    Ok(dunce::simplified(&abs.as_path()).into())
}


fn get_time_iso8601() -> io::Result<(String)> {
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();
    Ok(now.to_rfc3339())
}


fn print_help() {
    let help = "
        Author: Brian Kellogg
        Pull various file metadata.
        Usage: fmd <file path> [--pretty | -p]
        Options:
            -p, --pretty     Pretty print JSON
    ";
    println!("{}", help);
    process::exit(1)
}


fn get_args() -> io::Result<(String, bool)> {
    let args: Vec<String> = env::args().collect();
    let mut file_path = &String::new();
    let mut pprint = false;
    match args.len() {
        2 => {
            file_path = &args[1];
        },
        3 => {
            if &args[1] == "-p" || &args[1] == "--pretty" {
                file_path = &args[2];
            } else if &args[2] == "-p" || &args[2] == "--pretty" {
                file_path = &args[1];
            } else {
                print_help();
            }
            pprint = true;
        },
        4 => {
            if &args[1] == "-p" || &args[1] == "--pretty" {
                file_path = &args[2];
            } else if &args[2] == "-p" || &args[2] == "--pretty" {
                file_path = &args[1];
            } else {
                print_help();
            }
            pprint = true;
        }
        _ => { print_help() }
    };
    Ok((file_path.to_string(), pprint))
}


fn main() -> io::Result<()> {
    let (file_path, pprint) = get_args()?;
    let mut imps = false;
    let timestamp = get_time_iso8601()?;
    let path = convert_to_path(&file_path)?;
    let abs_path = get_abs_path(path)?.as_path().to_str().unwrap().to_string();
    let file = open_file(&path)?;
    let mut buffer = read_file_bytes(&file)?;
    let ssdeep = get_ssdeep_hash(&buffer)?;
    let mut mime_type = get_mimetype(&path)?;
    let (bytes, md5, sha1, sha256) = get_file_content_info(&file, &buffer)?;
    let bin = get_imports(path)?;
    print_log(timestamp, abs_path, 
                bytes, mime_type, md5, 
                sha1, sha256, ssdeep, 
                bin, pprint)?;
    Ok(())
}