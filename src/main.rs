extern crate tree_magic;
extern crate fuzzyhash;
extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization

use std::path::Path;
use std::{io, str};
use std::env;
use std::process;
use fuzzyhash::FuzzyHash;
use std::io::Read;
use serde::Serialize;


/*
    Help provided by Yandros on using traits: 
        https://users.rust-lang.org/t/refactor-struct-fn-with-macro/40093
*/
type Str = ::std::borrow::Cow<'static, str>;
trait Loggable : Serialize {
    /// convert struct to json
    fn to_log (self: &'_ Self) -> Str
    {
        ::serde_json::to_string(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    
    /// convert struct to json and report it out
    fn write_log (self: &'_ Self)
    {
        println!("{}", self.to_log());
    }
}
impl<T : ?Sized + Serialize> Loggable for T {}

#[derive(Serialize)]
pub struct MetaData {
    pub mime_type: String,
    pub fuzzy_hash: String
}
impl MetaData {
    pub fn new(
            mime_type: String,
            fuzzy_hash: String) -> MetaData {
        MetaData {
            mime_type,
            fuzzy_hash
        }
    }

    // convert struct to json and report it out
    pub fn report_log(&self) {
        self.write_log()
    }
}


// report out in json
fn print_log(mime_type: &str, fuzzy_hash: FuzzyHash) -> io::Result<()> {
    MetaData::new(mime_type.to_string(), fuzzy_hash.to_string()).report_log();
    Ok(())
}


fn get_mimetype(target_file: &Path) -> io::Result<String> {
    let mtype = tree_magic::from_filepath(target_file);

    Ok(mtype)
}


/* 
    See:    https://github.com/rustysec/fuzzyhash-rs
            https://docs.rs/fuzzyhash/latest/fuzzyhash/
*/
fn get_fuzzy_hash(target_file: &Path) -> io::Result<FuzzyHash> {
    let mut file = std::fs::File::open(target_file).unwrap();
    let mut fuzzy_hash = FuzzyHash::default();

    loop {
        let mut buffer = vec![0; 1024];
        let count = file.read(&mut buffer).unwrap();
    
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

    process::exit(1)
}


fn print_help() {
    println!("\nAuthor: Brian Kellogg");
    println!("Pull various file metadata.");
    println!("See: https://docs.rs/tree_magic/latest/tree_magic/\n");
    println!("\nUsage: fmd <file path>\n");
    process::exit(1)
}


fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 { print_help() }
    let file_path = &args[1];
    let path = convert_to_path(&file_path).unwrap();
    let mime_type = get_mimetype(path).unwrap();
    let fuzzy_hash = get_fuzzy_hash(path).unwrap();
    print_log(&mime_type, fuzzy_hash).unwrap();
    Ok(())
}