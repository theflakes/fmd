extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate whoami;

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{env, time::SystemTime, io};
use is_elevated::is_elevated;


lazy_static! { 
    pub static ref DEVICE_TYPE: String = whoami::distro();
}

fn get_time_iso8601() -> io::Result<String> {
    let now = SystemTime::now();
    let now: DateTime<Utc> = now.into();
    Ok(now.to_rfc3339())
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



impl Default for ImpHashes {
    fn default () -> ImpHashes {
        ImpHashes {
            md5: String::new(),
            md5_sorted: String::new(),
            ssdeep: String::new(),
            ssdeep_sorted: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ImpHashes {
    pub md5: String,
    pub md5_sorted: String,
    pub ssdeep: String,
    pub ssdeep_sorted: String
}


impl Default for ExpHashes {
    fn default () -> ExpHashes {
        ExpHashes {
            md5: String::new(),
            ssdeep: String::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ExpHashes {
    pub md5: String,
    pub ssdeep: String,
}


impl Default for Import {
    fn default () -> Import {
        Import {
            lib: String::new(),
            count: 0,
            names: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Import {
    pub lib: String,
    pub count: u32,
    pub names: Vec<String>
}


impl Default for Imports {
    fn default () -> Imports {
        Imports {
            hashes: ImpHashes::default(),
            lib_count: 0,
            func_count: 0,
            imports: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Imports {
    pub hashes: ImpHashes,
    pub lib_count: usize,
    pub func_count: usize,
    pub imports: Vec<Import>,
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

impl Default for BinSection {
    fn default () -> BinSection {
        BinSection {
            name: String::new(),
            entropy: 0.0,
            md5: String::new(),
            ssdeep: String::new(),
            virt_address: String::new(),
            raw_size: 0,
            virt_size: 0
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinSection {
    pub name: String,
    pub entropy: f32,
    pub md5: String,
    pub ssdeep: String,
    pub virt_address: String,
    pub raw_size: u32,
    pub virt_size: u32
}


impl Default for BinSections {
    fn default () -> BinSections {
        BinSections {
            total_sections: 0,
            total_raw_bytes: 0,
            total_virt_bytes: 0,
            sections: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinSections {
    pub total_sections: u16,
    pub total_raw_bytes: u32,
    pub total_virt_bytes: u32,
    pub sections: Vec<BinSection>
}

impl Default for BinLinker {
    fn default () -> BinLinker {
        BinLinker {
            major_version: 0,
            minor_version: 0
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinLinker {
    pub major_version: u8,
    pub minor_version: u8
}


impl Default for Exports {
    fn default () -> Exports {
        Exports {
            hashes: ExpHashes::default(),
            count: 0,
            names: Vec::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Exports {
    pub hashes: ExpHashes,
    pub count: usize,
    pub names: Vec<String>
}


impl Default for Binary {
    fn default () -> Binary {
        Binary {
            is_64: false,
            is_dotnet: false,
            is_lib: false,
            entry_point: String::new(),
            pe_info: PeFileInfo::default(),
            timestamps: BinTimestamps::default(),
            sections: BinSections::default(),
            linker: BinLinker::default(),
            imports: Imports::default(),
            exports: Exports::default()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Binary {
    pub is_64: bool,
    pub is_dotnet: bool,
    pub is_lib: bool,
    pub entry_point: String,
    pub pe_info: PeFileInfo,
    pub timestamps: BinTimestamps,
    pub linker: BinLinker,
    pub sections: BinSections,
    pub imports: Imports,
    pub exports: Exports
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


impl Default for Link {
    fn default () -> Link {
        Link {
            rel_path: String::new(),
            abs_path: String::new(),
            arguments: String::new(),
            working_dir: String::new(),
            icon_location: String::new(),
            hotkey: String::new(),
            comment: String::new(),
            show_command: String::new(),
            flags: String::new(),
            drive_type: String::new(),
            drive_serial_number: String::new(),
            volume_label: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Link {
    pub rel_path: String,
    pub abs_path: String,
    pub arguments: String,
    pub working_dir: String,
    pub icon_location: String,
    pub hotkey: String,
    pub comment: String,
    pub show_command: String,
    pub flags: String,
    pub drive_type: String,
    pub drive_serial_number: String,
    pub volume_label: String,
}


impl Default for RunTimeEnv {
    fn default () -> RunTimeEnv {
        RunTimeEnv {
            timestamp: get_time_iso8601().unwrap(),
            device_type: DEVICE_TYPE.to_string(),
            run_as_admin: is_elevated(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct RunTimeEnv {
    pub timestamp: String,
    pub device_type: String,
    pub run_as_admin: bool,
}


#[derive(Serialize)]
pub struct MetaData {
    pub runtime_env: RunTimeEnv,
    pub path: String,
    pub directory: String,
    pub filename: String,
    pub extension: String,
    pub bytes: u64,
    pub mime_type: String,
    pub is_hidden: bool,
    pub is_link: bool,
    pub link: Link,
    pub timestamps: FileTimestamps,
    pub entropy: f32,
    pub hashes: Hashes,
    pub ads: Vec<DataRun>,
    pub binary: Binary,
    pub strings: Vec<String>
}
impl MetaData {
    pub fn new(
            runtime_env: RunTimeEnv,
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
            strings: Vec<String>) -> MetaData {
        MetaData {
            runtime_env,
            path,
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