extern crate tree_magic;
extern crate fuzzyhash;

use std::path::Path;
use std::{io, str};
use std::env;
use std::process;
use fuzzyhash::FuzzyHash;
use std::io::Read;


fn get_mimetype(target_file: &Path) {
    let mtype = tree_magic::from_filepath(target_file);

    println!("{}", mtype);
}


/* 
    See:    https://github.com/rustysec/fuzzyhash-rs
            https://docs.rs/fuzzyhash/latest/fuzzyhash/

*/
fn get_fuzzy_hash(target_file: &Path) {
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
    
    println!("{}", fuzzy_hash);
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
    get_mimetype(path);
    get_fuzzy_hash(path);
    
    Ok(())
}