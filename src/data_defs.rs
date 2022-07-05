extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate whoami;

use serde::Serialize;
use std::env;


lazy_static! { 
    pub static ref DEVICE_TYPE: String = whoami::distro();
}

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


impl Default for Imports {
    fn default () -> Imports {
        Imports {
            lib: String::new(),
            count: 0,
            name: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Imports {
    pub lib: String,
    pub count: u32,
    pub name: Vec<String>
}

impl Default for FileTimestamps {
    fn default () -> FileTimestamps {
        FileTimestamps {
            access: String::new(),
            create: String::new(),
            modify: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct FileTimestamps {
    pub access: String,
    pub create: String,
    pub modify: String
}

impl Default for BinTimestamps {
    fn default () -> BinTimestamps {
        BinTimestamps {
            compile: String::new(),
            debug: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinTimestamps {
    pub compile: String,
    pub debug: String
}

impl Default for Binary {
    fn default () -> Binary {
        Binary {
            is_64: false,
            is_dotnet: false,
            is_lib: false,
            original_filename: String::new(),
            timestamps: BinTimestamps::default(),
            linker_major_version: 0,
            linker_minor_version: 0,
            imphash: String::new(),
            imphash_sorted: String::new(),
            imphash_ssdeep: String::new(),
            imphash_ssdeep_sorted: String::new(),
            imports_lib_count: 0,
            imports_func_count: 0,
            imports: Vec::new(),
            exports_count: 0,
            exports: Vec::new(),
            first_128_bytes: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Binary {
    pub is_64: bool,
    pub is_dotnet: bool,
    pub is_lib: bool,
    pub original_filename: String,
    pub timestamps: BinTimestamps,
    pub linker_major_version: u8,
    pub linker_minor_version: u8,
    pub imphash: String,
    pub imphash_sorted: String,
    pub imphash_ssdeep: String,
    pub imphash_ssdeep_sorted: String,
    pub imports_lib_count: u32,
    pub imports_func_count: u32,
    pub imports: Vec<Imports>,
    pub exports_count: u32,
    pub exports: Vec<String>,
    pub first_128_bytes: String
}


#[derive(Serialize)]
pub struct MetaData {
    pub timestamp: String,
    pub device_type: String,
    pub path: String,
    pub bytes: u64,
    pub mime_type: String,
    pub timestamps: FileTimestamps,
    pub entropy: f32,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: String,
    pub binary: Binary,
    pub strings: Vec<String>
}
impl MetaData {
    pub fn new(
            timestamp: String,
            device_type: String,
            path: String,
            bytes: u64,
            mime_type: String,
            timestamps: FileTimestamps,
            entropy: f32,
            md5: String,
            sha1: String,
            sha256: String,
            ssdeep: String,
            binary: Binary,
            strings: Vec<String>) -> MetaData {
        MetaData {
            timestamp,
            device_type,
            path,
            bytes,
            mime_type,
            timestamps,
            entropy,
            md5,
            sha1,
            sha256,
            ssdeep,
            binary,
            strings
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