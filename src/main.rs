extern crate tree_magic;
extern crate fuzzyhash;
extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate sha256;
extern crate crypto;
extern crate path_abs;
extern crate dunce;
extern crate chrono;

use std::path::Path;
use std::ptr::null;
use std::{io, str};
use std::env;
use std::process;
use std::borrow::Cow;
use fuzzyhash::FuzzyHash;
use std::io::{Read, Seek};
use serde::Serialize;
use crypto::digest::Digest;
use std::fs::{self, File};
use pelite::FileMap;
use path_abs::{PathAbs, PathInfo};
use chrono::prelude::{DateTime, Utc};
use std::time::SystemTime;
use pelite::pe32::Pe as pe32;
use pelite::pe64::Pe as pe64;
use pelite::pe32::PeFile as pefile32;
use pelite::pe64::PeFile as pefile64;


/*
    Help provided by Yandros on using traits: 
        https://users.rust-lang.org/t/refactor-struct-fn-with-macro/40093
*/
type Str = ::std::borrow::Cow<'static, str>;
trait Loggable : Serialize {
    /// convert struct to json
    fn to_log (self: &'_ Self) -> Str  {
        ::serde_json::to_string(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    fn to_pretty_log (self: &'_ Self) -> Str {
        ::serde_json::to_string_pretty(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    
    /// convert struct to json and report it out
    fn write_log (self: &'_ Self)
    {
        println!("{}", self.to_log());
    }
    fn write_pretty_log (self: &'_ Self)
    {
        println!("{}", self.to_pretty_log());
    }
}
impl<T : ?Sized + Serialize> Loggable for T {}


#[derive(Serialize)]
pub struct Imports {
    pub name: String,
    pub count: usize
}


#[derive(Serialize)]
pub struct MetaData {
    pub timestamp: String,
    pub path: String,
    pub arch: i8,
    pub bytes: u64,
    pub mime_type: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub fuzzy_hash: String,
    pub imports: Vec<Imports>
}
impl MetaData {
    pub fn new(
            timestamp: String,
            path: String,
            arch: i8,
            bytes: u64,
            mime_type: String,
            md5: String,
            sha1: String,
            sha256: String,
            fuzzy_hash: String,
            imports: Vec<Imports>) -> MetaData {
        MetaData {
            timestamp,
            path,
            arch,
            bytes,
            mime_type,
            md5,
            sha1,
            sha256,
            fuzzy_hash,
            imports
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }

    pub fn report_pretty_log(&self) {
        self.write_pretty_log()
    }
}


// report out in json
fn print_log(
                timestamp: String,
                path: String,
                arch: i8,
                bytes: u64,
                mime_type: String, 
                md5: String,
                sha1: String,
                sha256: String,
                fuzzy_hash: FuzzyHash,
                imports: Vec<Imports>,
                pprint: bool
            ) -> io::Result<()> {
    if pprint {
        MetaData::new(
            timestamp,
            path.to_string(),
            arch,
            bytes,
            mime_type, 
            md5, 
            sha1, 
            sha256, 
            fuzzy_hash.to_string(),
            imports
        ).report_pretty_log();
    } else {
        MetaData::new(
            timestamp,
            path.to_string(),
            arch,
            bytes,
            mime_type, 
            md5, 
            sha1, 
            sha256, 
            fuzzy_hash.to_string(),
            imports
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
fn get_fuzzy_hash(mut file: &std::fs::File) -> io::Result<FuzzyHash> {
    let mut fuzzy_hash = FuzzyHash::default();

    loop {
        let mut buffer = vec![0; 1024];
        let count = Read::read(&mut file, &mut buffer).unwrap();
    
        fuzzy_hash.update(buffer);
    
        if count < 1024 {
            break;
        }
    }
    
    fuzzy_hash.finalize();
    
    Ok(fuzzy_hash)
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
                                file: &std::fs::File
                            ) -> std::io::Result<(u64, String, String, String)> 
{
    let mut md5 = "".to_string();
    let mut sha1 = "".to_string();
    let mut sha256 = "".to_string();
    let bytes = file.metadata()?.len();
    if bytes != 0 { // don't bother with opening empty files
        let mut buffer = read_file_bytes(file)?;
        md5 = format!("{:x}", md5::compute(&buffer)).to_lowercase();
        sha1 = get_sha1(&buffer)?;
        sha256 = sha256::digest_bytes(&buffer);
        drop(buffer);
    } else {
        md5 = "d41d8cd98f00b204e9800998ecf8427e".to_string(); // md5 of empty file
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(); // sha1 of empty file
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(); // sha256 or empty file
    }
    Ok((bytes, md5, sha1, sha256))
}


fn dll_deps_32(image: &[u8]) -> pelite::Result<(Vec<Imports>)> {
	let mut file = match pefile32::from_bytes(image) {
        Ok(i) => i,
        Err(err) => return Err(err),
    };
    let mut imports: Vec<Imports> = Vec::new();
	let iat = file.imports()?;
    let mut imports: Vec<Imports> = Vec::new();
	for import in iat {
		let dll_name = import.dll_name()?;
        let num_of_functs = import.iat()?;
        let imp = Imports {
            name: dll_name.to_string(),
            count: num_of_functs.len()
        };
        imports.push(imp);
	}
	Ok((imports))
}


fn dll_deps_64(image: &[u8]) -> pelite::Result<(Vec<Imports>)> {
	let mut file = match pefile64::from_bytes(image) {
        Ok(i) => i,
        Err(err) => return Err(err),
    };
    //print!("{:?}", file.nt_headers());
    let mut imports: Vec<Imports> = Vec::new();
	let iat = file.imports()?;
    let mut imports: Vec<Imports> = Vec::new();
	for import in iat {
		let dll_name = import.dll_name()?;
        let num_of_functs = import.iat()?;
        let imp = Imports {
            name: dll_name.to_string(),
            count: num_of_functs.len()
        };
        imports.push(imp);
	}
	Ok((imports))
}


fn get_imports(path: &Path) -> std::io::Result<(Vec<Imports>, i8)> {
    let mut imports: Vec<Imports> = Vec::new();
    let mut arch: i8 = 0; // we need to find if bin is 32 or 64
    let file_map = FileMap::open(path)?;
	let mut results = dll_deps_64(file_map.as_ref());
    // look for an error on parsing 64 bit imports, this means the file is either 32 bit or not a bin at all
    if results.is_err() {
        results = dll_deps_32(file_map.as_ref());
        if !results.is_err() { 
            arch = 32;
            imports = results.unwrap();
        }
    } else { // 64 bit iat parsing was successful, therefore this is a 64 bit bin
        arch = 64;
        imports = results.unwrap();
    }

    Ok((imports, arch))
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
    println!("\nAuthor: Brian Kellogg");
    println!("Pull various file metadata.");
    println!("See: https://docs.rs/tree_magic/latest/tree_magic/\n");
    println!("Usage: fmd <file path>");
    println!("  Options:");
    println!("       -p, --pretty     Pretty print JSON");
    println!("\n");
    process::exit(1)
}


fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut pprint = false;
    let mut file_path = &String::new();
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
        _ => { print_help() }
    };
    let timestamp = get_time_iso8601()?;
    let path = convert_to_path(&file_path)?;
    let abs_path = get_abs_path(path)?.as_path().to_str().unwrap().to_string();
    let file = open_file(&path)?;
    let fuzzy_hash = get_fuzzy_hash(&file)?;
    let mut mime_type = get_mimetype(&path)?;
    let (bytes, md5, sha1, sha256) = get_file_content_info(&file)?;
    let (imports, arch) = get_imports(path)?;
    print_log(timestamp, abs_path, arch, bytes, mime_type, md5, sha1, sha256, fuzzy_hash, imports, pprint)?;
    Ok(())
}