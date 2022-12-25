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
    
    // convert struct to json and report it out
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
            access_fn: String::new(),
            access_si: String::new(),
            create_fn: String::new(),
            create_si: String::new(),
            modify_fn: String::new(),
            modify_si: String::new(),
            mft_record: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct FileTimestamps {
    pub access_fn: String,
    pub access_si: String,
    pub create_fn: String,
    pub create_si: String,
    pub modify_fn: String,
    pub modify_si: String,
    pub mft_record: String
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

impl Default for PeFileInfo {
    fn default () -> PeFileInfo {
        PeFileInfo {
            product_version: String::new(),
            original_filename: String::new(),
            file_description: String::new(),
            file_version: String::new(),
            product_name: String::new(),
            company_name: String::new(),
            internal_name: String::new(),
            legal_copyright: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeFileInfo {
    pub product_version: String,
    pub original_filename: String,
    pub file_description: String,
    pub file_version: String,
    pub product_name: String,
    pub company_name: String,
    pub internal_name: String,
    pub legal_copyright: String
}

impl Default for BinSections {
    fn default () -> BinSections {
        BinSections {
            total_sections: u16::default(),
            total_raw_size: u32::default(),
            total_virt_size: u32::default()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinSections {
    pub total_sections: u16,
    pub total_raw_size: u32,
    pub total_virt_size: u32
}

impl Default for ImpHashes {
    fn default () -> ImpHashes {
        ImpHashes {
            imphash: String::new(),
            imphash_sorted: String::new(),
            ssdeep: String::new(),
            ssdeep_sorted: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ImpHashes {
    pub imphash: String,
    pub imphash_sorted: String,
    pub ssdeep: String,
    pub ssdeep_sorted: String
}

impl Default for Binary {
    fn default () -> Binary {
        Binary {
            is_64: false,
            is_dotnet: false,
            is_lib: false,
            pe_info: PeFileInfo::default(),
            timestamps: BinTimestamps::default(),
            sections: BinSections::default(),
            linker_major_version: 0,
            linker_minor_version: 0,
            imphashes: ImpHashes::default(),
            imports_lib_count: 0,
            imports_func_count: 0,
            imports: Vec::new(),
            exports_count: 0,
            exports: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Binary {
    pub is_64: bool,
    pub is_dotnet: bool,
    pub is_lib: bool,
    pub pe_info: PeFileInfo,
    pub timestamps: BinTimestamps,
    pub linker_major_version: u8,
    pub linker_minor_version: u8,
    pub sections: BinSections,
    pub imphashes: ImpHashes,
    pub imports_lib_count: u32,
    pub imports_func_count: u32,
    pub imports: Vec<Imports>,
    pub exports_count: u32,
    pub exports: Vec<String>
}

impl Default for Hashes {
    fn default () -> Hashes {
        Hashes {
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            ssdeep: String::new()
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: String
}

impl Default for DataRun {
    fn default () -> DataRun {
        DataRun {
            name: String::new(),
            bytes: 0,
            first_256_bytes: String::new()
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct DataRun {
    pub name: String,
    pub bytes: u64,
    pub first_256_bytes: String
}

#[derive(Serialize)]
pub struct MetaData {
    pub timestamp: String,
    pub device_type: String,
    pub run_as_admin: bool,
    pub path: String,
    pub bytes: u64,
    pub mime_type: String,
    pub is_hidden: bool,
    pub timestamps: FileTimestamps,
    pub entropy: f32,
    pub hashes: Hashes,
    pub ads: Vec<DataRun>,
    pub binary: Binary,
    pub strings: Vec<String>
}
impl MetaData {
    pub fn new(
            timestamp: String,
            device_type: String,
            run_as_admin: bool,
            path: String,
            bytes: u64,
            mime_type: String,
            is_hidden: bool,
            timestamps: FileTimestamps,
            entropy: f32,
            hashes: Hashes,
            ads: Vec<DataRun>,
            binary: Binary,
            strings: Vec<String>) -> MetaData {
        MetaData {
            timestamp,
            device_type,
            run_as_admin,
            path,
            bytes,
            mime_type,
            is_hidden,
            timestamps,
            entropy,
            hashes,
            ads,
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