extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate docopt;
extern crate whoami;

use serde::Serialize;
use docopt::Docopt;
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


#[derive(Serialize)]
pub struct Imports {
    pub name: String,
    pub count: usize
}


#[derive(Serialize)]
pub struct MetaData {
    pub timestamp: String,
    pub device_type: String,
    pub path: String,
    pub arch: i8,
    pub bytes: u64,
    pub mime_type: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub fuzzy: String,
    pub imports: Vec<Imports>
}
impl MetaData {
    pub fn new(
            timestamp: String,
            device_type: String,
            path: String,
            arch: i8,
            bytes: u64,
            mime_type: String,
            md5: String,
            sha1: String,
            sha256: String,
            fuzzy: String,
            imports: Vec<Imports>) -> MetaData {
        MetaData {
            timestamp,
            device_type,
            path,
            arch,
            bytes,
            mime_type,
            md5,
            sha1,
            sha256,
            fuzzy,
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