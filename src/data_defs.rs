extern crate serde;             // needed for json serialization
extern crate serde_json;        // needed for json serialization
extern crate whoami;

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{env, time::SystemTime, io};
use is_elevated::is_elevated;
use std::collections::HashMap;


lazy_static! { 
    pub static ref DEVICE_TYPE: String = whoami::distro();
}

pub static INTERESTING_MIME_TYPES: &'static [&'static str] = &[
    "application/x-executable", // executable
    "application/x-msdownload", // self-extracting
    "application/x-sharedlib",  // elf binary
];

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


impl Default for Function {
    fn default () -> Function {
        Function {
            name: String::new(),
            more_interesting: false,
            info: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Function {
    pub name: String,
    pub more_interesting: bool,
    pub info: String
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
    pub names: Vec<Function>
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


/*
    Information to include on interesting binary imported functions
    Research by Jason Langston
*/
impl Default for Func {
    fn default () -> Func {
        Func {
            name: String::new(),
            desc: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Func {
    pub name: String,
    pub desc: String,
}
impl Func {
    pub fn new(
            name: String,
            desc: String) -> Func {
        Func {
            name,
            desc
        }
    }

    pub fn create(&self, name: &str, desc: &str) -> Func {
        Func::new(name.to_string(), desc.to_string())
    }
}

pub fn build_interesting_funcs() -> HashMap<String, Vec<Func>> {
    let func = Func::default();
    let mut dlls: HashMap<String, Vec<Func>> = HashMap::new();

    // advapi32.dll
    let funcs: Vec<Func> = [
        func.create("accept", "Permits an incom,ing connection attempt on a socket."),
        func.create("connectnamedpipe", "Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe."),
        func.create("createfilew", "Creates or opens a file or I/O device."),
        func.create("createmutexa", "Creates or opens a named or unamed mutex object."),
        func.create("createprocessa", "Creates a new process and its primary thread. Runs in the security context of the calling process."),
        func.create("createprocessw", "Creates a new process and its primary thread. Runs in the security context of the calling process."),
    ].to_vec();
    dlls.insert("advapi32.dll".to_string(), funcs);

    // crypt32.dll
    let funcs: Vec<Func> = [
        func.create("bitblt", "Permforms a bit-block transfer."),
        func.create("certopensystemstorea", "Opens the most common system certification store."),
    ].to_vec();
    dlls.insert("crypt32.dll".to_string(), funcs);

    // gdi32.dll
    let funcs: Vec<Func> = [
        func.create("bind", "Associates a local address with a socket."),
    ].to_vec();
    dlls.insert("gdi32.dll".to_string(), funcs);

    // icmp.dll
    let funcs: Vec<Func> = [
        func.create("IcmpCreateFile", "Opens a handle on which IPv4 ICMP echo requests can be issued."),
    ].to_vec();
    dlls.insert("icmp.dll".to_string(), funcs);

    // kernel32.dll
    let funcs: Vec<Func> = [
        func.create("connect", "Establishes a connection to a specified socket."),
        func.create("corbindtoruntimeex", ""),
        func.create("createfilea", "Creates or opens a file or I/O device."),
        func.create("createfilemappinga", "Creates or opens a named or unnamed file mapping object for a specified file."),
        func.create("createfilemappingw", "Creates or opens a named or unnamed file mapping object for a specified file."),
        func.create("createmutexw", "Creates or opens a named or unamed mutex object."),
        func.create("createremotethread", "Creates a thread that runs in the virtual address space of another process."),
        func.create("createservicea", "creates a service object and adds it to the specified service control manager database."),
        func.create("createservicew", "creates a service object and adds it to the specified service control manager database."),
        func.create("createtoolhelp32snapshot", "takes a snapshot of the specified processes, heaps,modules, and threads used by the processes."),
        func.create("cryptacquirecontexta", "Used to acquire a handle to a particular key container with a cryptographic service provider."),
        func.create("cryptacquirecontextw", "Used to acquire a handle to a particular key container with a cryptographic service provider."),
        func.create("deviceiocontrol", "Sends a control code directly to a specified device driver, causing the corresponding device to perform the ."),
        func.create("disconnectnamedpipe", "disconnects the server end of a named pipe instance from a client."),
        func.create("dllfunctioncall", "??."),
        func.create("enumcalendarinfoa", "enumerates calendar infromation for a specified locale."),
        func.create("enumprocesses", "Retrieves the process identifier for each process object in the system."),
        func.create("enumprocessmodules", "Retrieves a handle for each module in the specified process."),
        func.create("event_sink_addref", "??."),
        func.create("event_sink_queryinterface", "??."),
        func.create("event_sink_release", "??."),
        func.create("findfirstfilea", "searches a directory for a file or subdirectory with a name."),
        func.create("findfirstfileexa", "searches a directory for a file or subdirectory with a name."),
        func.create("findfirstfileexw", "searches a directory for a file or subdirectory with a name."),
        func.create("findfirstfilew", "searches a directory for a file or subdirectory with a name."),
        func.create("findnextfilea", "continues a file search for a previous call to the 'findfirstfile/findfirstfileex/findfirstfiletransacted' function."),
        func.create("findnextfilew", "continues a file search for a previous call to the 'findfirstfile/findfirstfileex/findfirstfiletransacted' function."),
        func.create("findresourcea", "Determines the location of a resource with specified type and name in the specified module."),
        func.create("findresourceexa", "determines the location of the resource with specified type,name, and language in the specified module."),
        func.create("findresourceexw", "determines the location of the resource with specified type,name, and language in the specified module."),
        func.create("findresourcew", "Determines the location of a resource with specified type and name in the specified module."),
        func.create("findwindowa", "Retrieves a handle to the top-level window whose class name and window name match the specified strings NO child windows, Not case-sensitive."),
        func.create("findwindowexa", "Retrieves a handle to a window whose class name and window name match the specified string. the function searches child windows NOT case-sensitive."),
        func.create("findwindowexw", "Retrieves a handle to a window whose class name and window name match the specified string. the function searches child windows NOT case-sensitive."),
        func.create("findwindoww", "Retrieves a handle to the top-level window whose class name and window name match the specified strings NO child windows, Not case-sensitive."),
        func.create("ftpcommanda", "Sends commands directly to an FTP server."),
        func.create("ftpcommandw", "Sends commands directly to an FTP server."),
        func.create("ftpcreatedirectorya", "Creates a new directory on the FTP server."),
        func.create("ftpcreatedirectoryw", "Creates a new directory on the FTP server."),
        func.create("ftpdeletefilea", "Deletes a file stored on the FTP server."),
        func.create("ftpfindfirstfilea", "Searches the specified directory of the given FTP session."),
        func.create("ftpgetcurrentdirectorya", "Retrieves the current directory for the specific FTP session."),
        func.create("ftpgetcurrentdirectoryw", "Retrieves the current directory for the specific FTP session."),
        func.create("ftpgetfilea", "Retries a file from the FTP server under the specified name, creating a new local file in the process."),
        func.create("ftpgetfilesize", "Retrieves the file size of the requested FTP resource."),
        func.create("ftpgetfilew", "Retries a file from the FTP server under the specified name, creating a new local file in the process."),
        func.create("ftpopenfilea", "Initiates access to a remote file on an FTP server for reading or writing."),
        func.create("ftpopenfilew", "Initiates access to a remote file on an FTP server for reading or writing."),
        func.create("ftpputfilea", "Stores a file on the FTP server."),
        func.create("ftpputfilew", "Stores a file on the FTP server."),
        func.create("ftpremovedirectorya", "Removes the specified directory on the FTP server."),
        func.create("ftprenamefilea", "Renames a file stored on the FTP server."),
        func.create("ftpsetcurrentdirectorya", "Changes to a different working directory on the FTP server."),
        func.create("ftpsetcurrentdirectoryw", "Changes to a different working directory on the FTP server."),
        func.create("getadaptersinfo", "retrieves adapter information for the local computer (for windows XP and later use GetAdaptersAddresses)."),
        func.create("getasynckeystate", "Determines whether a key is up or down at the time the function is called."),
        func.create("getdc", " retrieves a handle to a device context for the client area of a specified window or for the entire screen."),
        func.create("getdcex", "an extension to the GetDC function, which gives an application more control over how and whether clipping occurs in the client area."),
        func.create("geterrorinfo", "Obtains the error information pointer set by seterrorinfo."),
        func.create("getforegroundwindow", "Retrieves a handle to the foreground window."),
        func.create("gethostbyname", "retrieves host information corresponding to a host name from a host database."),
        func.create("gethostname", "retrieves the standard host name for the local computer."),
        func.create("getkeystate", "Retrieves the status of the specified virtual key."),
        func.create("getmodulefilenamea", "Retrieves the fully qualified path for the file that contains the specified module."),
        func.create("getmodulefilenamew", "Retrieves the fully qualified path for the file that contains the specified module."),
        func.create("getmodulehandlea", "Retrieves a module handle for the specified module."),
        func.create("getmodulehandleexa", "Retrieves a module handle for the specified module and increments the module's reference count ."),
        func.create("getmodulehandleexw", "Retrieves a module handle for the specified module and increments the module's reference count."),
        func.create("getmodulehandlew", "Retrieves a module handle for the specified module."),
        func.create("GetStartupInfoA", "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was created."),
        func.create("GetStartupInfoW", "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was created."),
        func.create("GetSystemDefaultLangID", "Returns the language identifier for the system locale."),
        func.create("GetTempPathA", "Retrieves the path of the directory designated for temporary files."),
        func.create("GetTempPathW", "Retrieves the path of the directory designated for temporary files."),
        func.create("GetThreadContext", "Retrieves the context of the specified thread."),
        func.create("GetVersion", "return value includes the major and minor version numbers of the operating system in the low-order word, and information about the operating system platform in the high-order word. (Unavailable for release after windows 8.1)."),
        func.create("GetVersionExA", "??"),
        func.create("GetVersionExW", "??"),
        func.create("GetWindowsDirectoryA", "Retrieves the path of the Windows directory."),
        func.create("GetWindowsDirectoryW", "Retrieves the path of the Windows directory."),
        func.create("LoadLibraryA", "Loads the specified module into the address space of the calling process."),
        func.create("LoadLibraryExA", "Loads the specified module into the address space of the calling process."),
        func.create("LoadLibraryExW", "Loads the specified module into the address space of the calling process."),
        func.create("LoadLibraryW", "Loads the specified module into the address space of the calling process."),
        func.create("VirtualAllocEx", "Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero."),
    ].to_vec();
    dlls.insert("kernel32.dll".to_string(), funcs);

    // mpr.dll
    let funcs: Vec<Func> = [
        func.create("certopensystemstorew", "Opens the most common system certification store."),
        func.create("wnetuseconnectionw", "Makes a connection to a network resource."),
    ].to_vec();
    dlls.insert("mpr.dll".to_string(), funcs);

    // mscoree.dll
    let funcs: Vec<Func> = [
        func.create("controlservice", "Sends a control code to a service."),
    ].to_vec();
    dlls.insert("mscoree.dll".to_string(), funcs);

    // netapi32.dll
    let funcs: Vec<Func> = [
        func.create("NetShareEnum", "Retrieves information about each shared resource on a server."),
        func.create("NetWkstaGetInfo", "Returns information about the configuration of a workstation."),
    ].to_vec();
    dlls.insert("netapi32.dll".to_string(), funcs);

    // oleaut32.dll
    let funcs: Vec<Func> = [
        func.create("MethCallEngine", "??"),
        func.create("ProcCallEngine", "??"),
        func.create("SafeArrayCreate", "Creates a new array descriptor, allocates and initializes the data for the array, and returns a pointer to the new array descriptor."),
        func.create("SafeArrayGetLBound", "Gets the lower bound for any dimension of the specified safe array."),
        func.create("SafeArrayGetUBound", "Gets the upper bound for any dimension of the specified safe array."),
        func.create("SafeArrayPtrOfIndex", "Gets a pointer to an array element."),
        func.create("SysAllocStringLen", "Allocates a new string, copies the specified number of characters from the passed string, and appends a null-terminating character."),
        func.create("SysFreeString", "Deallocates a string allocated previously by SysAllocString, SysAllocStringByteLen, SysReAllocString, SysAllocStringLen, or SysReAllocStringLen."),
        func.create("SysReAllocStringLen", "Creates a new BSTR containing a specified number of characters from an old BSTR, and frees the old BSTR."),
        func.create("VariantChangeType", "Converts a variant from one type to another."),
        func.create("VariantClear", "Clears a variant.."),
        func.create("VariantCopy", "Frees the destination variant and makes a copy of the source variant."),
        func.create("VariantCopyInd", "Frees the destination variant and makes a copy of the source variant, performing the necessary indirection if the source is specified to be VT_BYREF."),
        func.create("VariantInit", "Initializes a variant."),
    ].to_vec();
    dlls.insert("oleaut32.dll".to_string(), funcs);

    // rpcrt4.dll
    let funcs: Vec<Func> = [
        func.create("AdjustTokenPrivileges", "Enables or disabled Privileges."),
    ].to_vec();
    dlls.insert("rpcrt4.dll".to_string(), funcs);

    // urlmon.dll
    let funcs: Vec<Func> = [
        func.create("URLDownloadToFileA", "??"),
        func.create("URLDownloadToFileW", "??"),
    ].to_vec();
    dlls.insert("urlmon.dll".to_string(), funcs);

    // user32.dll
    let funcs: Vec<Func> = [
        func.create("getprocaddress", "Retrieves the address of an exported function or variable from the specified dynamic-link library."),
    ].to_vec();
    dlls.insert("user32.dll".to_string(), funcs);

    // vbe7.dll
    let funcs: Vec<Func> = [
        func.create("__vbaexcepthandler", "??"),
    ].to_vec();
    dlls.insert("vbe7.dll".to_string(), funcs);

    // winhttp.dll
    let funcs: Vec<Func> = [
        func.create("WinHttpCloseHandle", "closes a single HINTERNET handle."),
        func.create("WinHttpConnect", "specifies the initial target server of an HTTP request and returns an HINTERNET connection handle to an HTTP session for that initial target."),
        func.create("WinHttpOpen", "nitializes, for an application, the use of WinHTTP functions and returns a WinHTTP-session handle."),
        func.create("WinHttpOpenRequest", "creates an HTTP request handle."),
        func.create("WinHttpQueryDataAvailable", "function returns the amount of data, in bytes, available to be read with WinHttpReadData."),
        func.create("WinHttpQueryHeaders", " retrieves header information associated with an HTTP request."),
        func.create("WinHttpReadData", "reads data from a handle opened by the WinHttpOpenRequest function."),
        func.create("WinHttpReceiveResponse", "waits to receive the response to an HTTP request initiated by WinHttpSendRequest."),
        func.create("winhttpsendrequest", "sends the specified request to the HTTP server."),
    ].to_vec();
    dlls.insert("winhttp.dll".to_string(), funcs);

    // wininet.dll
    let funcs: Vec<Func> = [
        func.create("HttpOpenRequestA", "Creates an HTTP request handle."),
        func.create("HttpOpenRequestW", "Creates an HTTP request handle."),
        func.create("HttpQueryInfoA", "Retrieves header information associated with an HTTP request."),
        func.create("HttpSendRequestA", "Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx."),
        func.create("HttpSendRequestW", "Sends the specified request to the HTTP server, allowing callers to send extra data beyond what is normally passed to HttpSendRequestEx."),
        func.create("InternetCloseHandle", "Closes a single Internet handle."),
        func.create("InternetConnectA", "Opens an File Transfer Protocol or HTTP session for a given site."),
        func.create("InternetConnectW", "Opens an File Transfer Protocol or HTTP session for a given site."),
        func.create("InternetCrackUrlA", "Cracks a URL into its component parts.."),
        func.create("InternetCrackUrlW", "Cracks a URL into its component parts.."),
        func.create("InternetFindNextFileA", "Continues a file search started as a result of a previous call to FtpFindFirstFile."),
        func.create("InternetFindNextFileW", "Continues a file search started as a result of a previous call to FtpFindFirstFile."),
        func.create("InternetOpenA", "Initializes an application's use of the WinINet functions.."),
        func.create("InternetOpenUrlA", "Opens a resource specified by a complete FTP or HTTP URL."),
        func.create("InternetOpenUrlW", "Opens a resource specified by a complete FTP or HTTP URL."),
        func.create("InternetOpenW", "Initializes an application's use of the WinINet functions.."),
        func.create("InternetQueryDataAvailable", "Queries the server to determine the amount of data available."),
        func.create("InternetReadFile", "Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function."),
    ].to_vec();
    dlls.insert("wininet.dll".to_string(), funcs);

    // ws2_32.dll
    let funcs: Vec<Func> = [
        func.create("wsaasyncgethostbyname", "asynchronously retrieves host information that corresponds to a host name."),
        func.create("getprofileinta", "Retrieves an integer from a key in the specified section of the Win.ini file.."),
        func.create("inet_addr", " converts a string containing an IPv4 dotted-decimal address into a proper address for the IN_ADDR structure."),
    ].to_vec();
    dlls.insert("ws2_32.dll".to_string(), funcs);

    return dlls
}