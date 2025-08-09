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
    pub static ref DLLS: HashMap<String, Vec<Func>> = build_interesting_funcs();
}

pub static INTERESTING_MIME_TYPES: &'static [&'static str] = &[
    "application/vnd.microsoft.portable-executable",
    "application/hta",
    "application/mac-binary",
    "application/macbinary",
    "application/octet-stream",
    "application/x-binary",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-macbinary",
    "application/x-ms-dos-executable",
    "application/x-msdownload",
    "application/x-sharedlib",
    "application/x-elf",
    "application/x-mach-binary",
    "application/wasm",
    "text/javascript",
    "application/x-csh",
    "application/x-shellscript",
    "text/x-shellscript",
    "text/x-nushell",
    "application/x-nuscript",
];

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    #[default] // Sets Unknown as the default variant
    Unknown,
}

#[derive(Serialize, Clone, Debug, PartialEq, Default)]
pub enum Architecture {
    X86,       // 32-bit Intel/AMD
    X86_64,    // 64-bit Intel/AMD
    Arm,       // 32-bit ARM
    AArch64,   // 64-bit ARM (sometimes called ARM64)
    Mips,
    PowerPC,
    RiscV,
    Itanium,   // IA-64
    #[default] // Sets Unknown as the default variant
    Unknown,
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
            md5_sorted: String::new(),
            ssdeep: String::new(),
            ssdeep_sorted: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ExpHashes {
    pub md5: String,
    pub md5_sorted: String,
    pub ssdeep: String,
    pub ssdeep_sorted: String,
}


impl Default for Function {
    fn default() -> Function {
        Function {
            name: String::new(),
            more_interesting: None,
            info: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Function {
    pub name: String,
    pub more_interesting: Option<bool>,
    pub info: String,
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


impl Default for PeTimestamps {
    fn default () -> PeTimestamps {
        PeTimestamps {
            compile: String::new(),
            debug: String::new()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeTimestamps {
    pub compile: String,
    pub debug: String
}

impl Default for PeLinker {
    fn default () -> PeLinker {
        PeLinker {
            major_version: 0,
            minor_version: 0
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeLinker {
    pub major_version: u8,
    pub minor_version: u8
}


impl Default for PeInfo {
    fn default () -> PeInfo {
        PeInfo {
            timestamps: PeTimestamps::default(),
            product_version: String::new(),
            original_filename: String::new(),
            file_description: String::new(),
            file_version: String::new(),
            product_name: String::new(),
            company_name: String::new(),
            internal_name: String::new(),
            legal_copyright: String::new(),
            linker: PeLinker::default(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeInfo {
    pub timestamps: PeTimestamps,
    pub product_version: String,
    pub original_filename: String,
    pub file_description: String,
    pub file_version: String,
    pub product_name: String,
    pub company_name: String,
    pub internal_name: String,
    pub legal_copyright: String,
    pub linker: PeLinker,
}


impl Default for ElfInfo {
    fn default () -> ElfInfo {
        ElfInfo {
            os_abi: String::new(),
            abi_version: 0,
            file_type: String::new(),
            object_version: 0,
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ElfInfo {
    pub os_abi: String,
    pub abi_version: u8,
    pub file_type: String,
    pub object_version: u8,
}

impl Default for MachOInfo {
    fn default () -> MachOInfo {
        MachOInfo {
            file_type: String::new(),
            flags: String::new(),
            cpu_subtype: String::new(),
            ncmds: 0,
            sizeofcmds: 0,
        }
    }
}
 #[derive(Serialize, Clone)]
pub struct MachOInfo {
     pub file_type: String,
     pub flags: String,
     pub cpu_subtype: String,
     pub ncmds: u32,
     pub sizeofcmds: u32,
}


impl Default for BinaryInfo {
    fn default () -> BinaryInfo {
        BinaryInfo {
            format: BinaryFormat::Unknown,
            arch: Architecture::Unknown,
            is_64: false,
            is_dotnet: false,
            is_lib: false,
            entry_point: String::new(),
            elf_info: ElfInfo::default(),
            pe_info: PeInfo::default(),
            macho_info: MachOInfo::default(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub arch: Architecture,
    pub is_64: bool,
    pub is_dotnet: bool,
    pub is_lib: bool,
    pub entry_point: String,
    pub elf_info: ElfInfo,
    pub pe_info: PeInfo,
    pub macho_info: MachOInfo,
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
            virt_size: 0,
            elf_comment_or_note_content: None,
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
    pub virt_size: u32,
    pub elf_comment_or_note_content: Option<String>,
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
            binary_info: BinaryInfo::default(),
            sections: BinSections::default(),
            imports: Imports::default(),
            exports: Exports::default()
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Binary {
    pub binary_info: BinaryInfo,
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
            // drive_type: String::new(),
            // drive_serial_number: String::new(),
            // volume_label: String::new(),
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
    // pub drive_type: String,
    // pub drive_serial_number: String,
    // pub volume_label: String,
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

    // PE

    // advapi32.dll
    let funcs: Vec<Func> = [
        func.create("accept", "Permits an incoming connection attempt on a socket."),
        func.create("connectnamedpipe", "Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe."),
        func.create("createfilew", "Creates or opens a file or I/O device. The most commonly used I/O devices are files, file streams, directories, physical disks, volumes, console buffers, tape drives, communications resources, mailslots, and pipes."),
        func.create("createmutexa", "Creates or opens a named or unnamed mutex object."),
        func.create("createprocessa", "Creates a new process and its primary thread. The new process runs in the security context of the calling process."),
        func.create("createprocessw", "Creates a new process and its primary thread. The new process runs in the security context of the calling process. This is the Unicode version of CreateProcessA."),
    ].to_vec();
    dlls.insert("advapi32.dll".to_string(), funcs);

    // crypt32.dll
    let funcs: Vec<Func> = [
        func.create("bitblt", "Performs a bit-block transfer of color data from one device context to another."),
        func.create("certopensystemstorea", "Opens the most common system certificate store using ANSI character encoding."),
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
        func.create("corbindtoruntimeex", "Enables unmanaged hosts to load the common language runtime (CLR) into a process, allowing for the specification of runtime behavior through various flags."),
        func.create("createfilea", "Creates or opens a file or I/O device. This is the ANSI version."),
        func.create("createfilemappinga", "Creates or opens a named or unnamed file mapping object for a specified file. This is the ANSI version."),
        func.create("createfilemappingw", "Creates or opens a named or unnamed file mapping object for a specified file. This is the Unicode version."),
        func.create("createmutexw", "Creates or opens a named or unnamed mutex object. This is the Unicode version."),
        func.create("createremotethread", "Creates a thread that runs in the virtual address space of another process."),
        func.create("createservicea", "Creates a service object and adds it to the specified service control manager database. This is the ANSI version."),
        func.create("createservicew", "Creates a service object and adds it to the specified service control manager database. This is the Unicode version."),
        func.create("createtoolhelp32snapshot", "Takes a snapshot of the specified processes, heaps, modules, and threads used by the system."),
        func.create("cryptacquirecontexta", "Acquires a handle to a particular key container within a cryptographic service provider (CSP). This is the ANSI version."),
        func.create("cryptacquirecontextw", "Acquires a handle to a particular key container within a cryptographic service provider (CSP). This is the Unicode version."),
        func.create("deviceiocontrol", "Sends a control code directly to a specified device driver, causing the corresponding device to perform the specified operation."),
        func.create("disconnectnamedpipe", "Disconnects the server end of a named pipe instance from a client process."),
        func.create("dllfunctioncall", "Calls a function from a dynamically linked library (DLL). This process involves loading the DLL into memory, locating the function within the DLL, and then invoking the function with the appropriate parameters."),
        func.create("enumcalendarinfoa", "Enumerates calendar information for a specified locale. This is the ANSI version."),
        func.create("enumprocesses", "Retrieves the process identifier for each process object in the system."),
        func.create("enumprocessmodules", "Retrieves a handle for each module in the specified process."),
        func.create("event_sink_addref", "Increments the reference count for an event sink object in COM programming, ensuring that the object remains in memory as long as it is needed."),
        func.create("event_sink_queryinterface", "Retrieves pointers to the supported interfaces on an event sink object."),
        func.create("event_sink_release", "Decrements the reference count for an event sink object in COM programming."),
        func.create("findfirstfilea", "Searches a directory for a file or subdirectory with a name that matches a specific name or partial name. This is the ANSI version."),
        func.create("findfirstfileexa", "Searches a directory for a file or subdirectory with a name and attributes that match those specified. This is the ANSI version."),
        func.create("findfirstfileexw", "Searches a directory for a file or subdirectory with a name and attributes that match those specified. This is the Unicode version."),
        func.create("findfirstfilew", "Searches a directory for a file or subdirectory with a name that matches a specific name or partial name. This is the Unicode version."),
        func.create("findnextfilea", "Continues a file search from a previous call to the FindFirstFile, FindFirstFileEx, or FindFirstFileTransacted function. This is the ANSI version."),
        func.create("findnextfilew", "Continues a file search from a previous call to the FindFirstFile, FindFirstFileEx, or FindFirstFileTransacted function. This is the Unicode version."),
        func.create("findresourcea", "Determines the location of a resource with the specified type and name in the specified module. This is the ANSI version."),
        func.create("findresourceexa", "Determines the location of the resource with the specified type, name, and language in the specified module. This is the ANSI version."),
        func.create("findresourceexw", "Determines the location of the resource with the specified type, name, and language in the specified module. This is the Unicode version."),
        func.create("findresourcew", "Determines the location of a resource with the specified type and name in the specified module. This is the Unicode version."),
        func.create("findwindowa", "Retrieves a handle to the top-level window whose class name and window name match the specified strings. This function does not search child windows and is not case sensitive. This is the ANSI version."),
        func.create("findwindowexa", "Retrieves a handle to a window whose class name and window name match the specified strings. The function searches child windows, but is not case sensitive. This is the ANSI version."),
        func.create("findwindowexw", "Retrieves a handle to a window whose class name and window name match the specified strings. The function searches child windows, but is not case sensitive. This is the Unicode version."),
        func.create("findwindoww", "Retrieves a handle to the top-level window whose class name and window name match the specified strings. This function does not search child windows and is not case sensitive. This is the Unicode version."),
        func.create("ftpcommanda", "Sends commands directly to an FTP server. This is the ANSI version."),
        func.create("ftpcommandw", "Sends commands directly to an FTP server. This is the Unicode version."),
        func.create("ftpcreatedirectorya", "Creates a new directory on the FTP server. This is the ANSI version."),
        func.create("ftpcreatedirectoryw", "Creates a new directory on the FTP server. This is the Unicode version."),
        func.create("ftpdeletefilea", "Deletes a file stored on the FTP server. This is the ANSI version."),
        func.create("ftpfindfirstfilea", "Searches the specified directory of the given FTP session. This is the ANSI version."),
        func.create("ftpgetcurrentdirectorya", "Retrieves the current directory for the specified FTP session. This is the ANSI version."),
        func.create("ftpgetcurrentdirectoryw", "Retrieves the current directory for the specified FTP session. This is the Unicode version."),
        func.create("ftpgetfilea", "Retrieves a file from the FTP server under the specified name, creating a new local file in the process. This is the ANSI version."),
        func.create("ftpgetfilesize", "Retrieves the file size of the requested FTP resource."),
        func.create("ftpgetfilew", "Retrieves a file from the FTP server under the specified name, creating a new local file in the process. This is the Unicode version."),
        func.create("ftpopenfilea", "Initiates access to a remote file on an FTP server for reading or writing. This is the ANSI version."),
        func.create("ftpopenfilew", "Initiates access to a remote file on an FTP server for reading or writing. This is the Unicode version."),
        func.create("ftpputfilea", "Stores a file on the FTP server. This is the ANSI version."),
        func.create("ftpputfilew", "Stores a file on the FTP server. This is the Unicode version."),
        func.create("ftpremovedirectorya", "Removes the specified directory on the FTP server. This is the ANSI version."),
        func.create("ftprenamefilea", "Renames a file stored on the FTP server. This is the ANSI version."),
        func.create("ftpsetcurrentdirectorya", "Changes to a different working directory on the FTP server. This is the ANSI version."),
        func.create("ftpsetcurrentdirectoryw", "Changes to a different working directory on the FTP server. This is the Unicode version."),
        func.create("getadaptersinfo", "Retrieves adapter information for the local computer. For Windows XP and later, use GetAdaptersAddresses instead."),
        func.create("getasynckeystate", "Determines whether a key is up or down at the time the function is called, and whether the key was pressed after a previous call to GetAsyncKeyState."),
        func.create("getdc", "Retrieves a handle to a device context (DC) for the client area of a specified window or for the entire screen."),
        func.create("getdcex", "Retrieves a handle to a device context (DC) for the client area of a specified window or for the entire screen. It gives an application more control over how and whether clipping occurs in the client area."),
        func.create("geterrorinfo", "Obtains the error information pointer set by SetErrorInfo."),
        func.create("getforegroundwindow", "Retrieves a handle to the foreground window (the window with which the user is currently working)."),
        func.create("gethostbyname", "Retrieves host information corresponding to a hostname from a host database."),
        func.create("gethostname", "Retrieves the standard host name for the local computer."),
        func.create("getkeystate", "Retrieves the status of the specified virtual key. The status specifies whether the key is up, down, or toggled (on, off alternating each time the key is pressed)."),
        func.create("getmodulefilenamea", "Retrieves the fully qualified path for the file that contains the specified module. The module must have been loaded by the current process. This is the ANSI version."),
        func.create("getmodulefilenamew", "Retrieves the fully qualified path for the file that contains the specified module. The module must have been loaded by the current process. This is the Unicode version."),
        func.create("getmodulehandlea", "Retrieves a module handle for the specified module. The module must have been loaded by the calling process. This is the ANSI version."),
        func.create("getmodulehandleexa", "Retrieves a module handle for the specified module and increments the module's reference count. This is the ANSI version."),
        func.create("getmodulehandleexw", "Retrieves a module handle for the specified module and increments the module's reference count. This is the Unicode version."),
        func.create("getmodulehandlew", "Retrieves a module handle for the specified module. The module must have been loaded by the calling process. This is the Unicode version."),
        func.create("GetStartupInfoA", "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was created. This is the ANSI version."),
        func.create("GetStartupInfoW", "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was created. This is the Unicode version."),
        func.create("GetSystemDefaultLangID", "Returns the language identifier for the system locale."),
        func.create("GetTempPathA", "Retrieves the path of the directory designated for temporary files. This is the ANSI version."),
        func.create("GetTempPathW", "Retrieves the path of the directory designated for temporary files. This is the Unicode version."),
        func.create("GetThreadContext", "Retrieves the context of the specified thread."),
        func.create("GetVersion", "Returns the major and minor version numbers of the operating system in the low-order word, and information about the operating system platform in the high-order word. (Unavailable for release after Windows 8.1)."),
        func.create("GetVersionExA", "Retrieves information about the current operating system, including major and minor version numbers, build number, platform, and service pack information. This is the ANSI version."),
        func.create("GetVersionExW", "Retrieves information about the current operating system, including major and minor version numbers, build number, platform, and service pack information. This is the Unicode version."),
        func.create("GetWindowsDirectoryA", "Retrieves the path of the Windows directory. This is the ANSI version."),
        func.create("GetWindowsDirectoryW", "Retrieves the path of the Windows directory. This is the Unicode version."),
        func.create("LoadLibraryA", "Loads the specified module into the address space of the calling process. This is the ANSI version."),
        func.create("LoadLibraryExA", "Loads the specified module into the address space of the calling process, with additional control over loading behavior. This is the ANSI version."),
        func.create("LoadLibraryExW", "Loads the specified module into the address space of the calling process, with additional control over loading behavior. This is the Unicode version."),
        func.create("LoadLibraryW", "Loads the specified module into the address space of the calling process. This is the Unicode version."),
        func.create("VirtualAllocEx", "Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero."),
    ].to_vec();
    dlls.insert("kernel32.dll".to_string(), funcs);

    // mpr.dll
    let funcs: Vec<Func> = [
        func.create("certopensystemstorew", "Opens the most common system certification store. This is the Unicode version."),
        func.create("wnetuseconnectionw", "Makes a connection to a network resource. This is the Unicode version."),
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
        func.create("MethCallEngine", "Internal function used by the COM method invocation mechanism."),
        func.create("ProcCallEngine", "Internal function used by the COM procedure call mechanism."),
        func.create("SafeArrayCreate", "Creates a new array descriptor, allocates and initializes the data for the array, and returns a pointer to the new array descriptor."),
        func.create("SafeArrayGetLBound", "Gets the lower bound for any dimension of the specified safe array."),
        func.create("SafeArrayGetUBound", "Gets the upper bound for any dimension of the specified safe array."),
        func.create("SafeArrayPtrOfIndex", "Gets a pointer to an array element based on a set of indexes."),
        func.create("SysAllocStringLen", "Allocates a new string, copies the specified number of characters from the passed string, and appends a null-terminating character."),
        func.create("SysFreeString", "Deallocates a string allocated previously by SysAllocString, SysAllocStringByteLen, SysReAllocString, SysAllocStringLen, or SysReAllocStringLen."),
        func.create("SysReAllocStringLen", "Creates a new BSTR containing a specified number of characters from an old BSTR, and frees the old BSTR."),
        func.create("VariantChangeType", "Converts a variant from one type to another."),
        func.create("VariantClear", "Clears a variant by setting its type to VT_EMPTY and its value to zero."),
        func.create("VariantCopy", "Frees the destination variant and makes a copy of the source variant."),
        func.create("VariantCopyInd", "Frees the destination variant and makes a copy of the source variant, performing the necessary indirection if the source is specified to be VT_BYREF."),
        func.create("VariantInit", "Initializes a variant by setting its type to VT_EMPTY."),
    ].to_vec();
    dlls.insert("oleaut32.dll".to_string(), funcs);

    // rpcrt4.dll
    let funcs: Vec<Func> = [
        func.create("AdjustTokenPrivileges", "Enables or disables privileges in the specified access token."),
    ].to_vec();
    dlls.insert("rpcrt4.dll".to_string(), funcs);

    // urlmon.dll
    let funcs: Vec<Func> = [
        func.create("URLDownloadToFileA", "Downloads the specified resource to a local file. This is the ANSI version."),
        func.create("URLDownloadToFileW", "Downloads the specified resource to a local file. This is the Unicode version."),
    ].to_vec();
    dlls.insert("urlmon.dll".to_string(), funcs);

    // user32.dll
    let funcs: Vec<Func> = [
        func.create("getprocaddress", "Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL)."),
    ].to_vec();
    dlls.insert("user32.dll".to_string(), funcs);

    // vbe7.dll
    let funcs: Vec<Func> = [
        func.create("__vbaexcepthandler", "Internal exception handler used by Visual Basic for Applications runtime."),
    ].to_vec();
    dlls.insert("vbe7.dll".to_string(), funcs);

    // winhttp.dll
    let funcs: Vec<Func> = [
        func.create("WinHttpCloseHandle", "Closes a single HINTERNET handle."),
        func.create("WinHttpConnect", "Specifies the initial target server of an HTTP request and returns an HINTERNET connection handle to an HTTP session for that initial target."),
        func.create("WinHttpOpen", "Initializes, for an application, the use of WinHTTP functions and returns a WinHTTP-session handle."),
        func.create("WinHttpOpenRequest", "Creates an HTTP request handle."),
        func.create("WinHttpQueryDataAvailable", "Returns the amount of data, in bytes, available to be read with WinHttpReadData."),
        func.create("WinHttpQueryHeaders", "Retrieves header information associated with an HTTP request."),
        func.create("WinHttpReadData", "Reads data from a handle opened by the WinHttpOpenRequest function."),
        func.create("WinHttpReceiveResponse", "Waits to receive the response to an HTTP request initiated by WinHttpSendRequest."),
        func.create("winhttpsendrequest", "Sends the specified request to the HTTP server."),
    ].to_vec();
    dlls.insert("winhttp.dll".to_string(), funcs);

    // wininet.dll
    let funcs: Vec<Func> = [
        func.create("HttpOpenRequestA", "Creates an HTTP request handle. This is the ANSI version."),
        func.create("HttpOpenRequestW", "Creates an HTTP request handle. This is the Unicode version."),
        func.create("HttpQueryInfoA", "Retrieves header information associated with an HTTP request. This is the ANSI version."),
        func.create("HttpSendRequestA", "Sends the specified request to the HTTP server. This is the ANSI version."),
        func.create("HttpSendRequestW", "Sends the specified request to the HTTP server. This is the Unicode version."),
        func.create("InternetCloseHandle", "Closes a single Internet handle."),
        func.create("InternetConnectA", "Opens an FTP or HTTP session for a given site. This is the ANSI version."),
        func.create("InternetConnectW", "Opens an FTP or HTTP session for a given site. This is the Unicode version."),
        func.create("InternetCrackUrlA", "Cracks a URL into its component parts. This is the ANSI version."),
        func.create("InternetCrackUrlW", "Cracks a URL into its component parts. This is the Unicode version."),
        func.create("InternetFindNextFileA", "Continues a file search started by a previous call to FtpFindFirstFile. This is the ANSI version."),
        func.create("InternetFindNextFileW", "Continues a file search started by a previous call to FtpFindFirstFile. This is the Unicode version."),
        func.create("InternetOpenA", "Initializes an application's use of the WinINet functions. This is the ANSI version."),
        func.create("InternetOpenUrlA", "Opens a resource specified by a complete FTP or HTTP URL. This is the ANSI version."),
        func.create("InternetOpenUrlW", "Opens a resource specified by a complete FTP or HTTP URL. This is the Unicode version."),
        func.create("InternetOpenW", "Initializes an application's use of the WinINet functions. This is the Unicode version."),
        func.create("InternetQueryDataAvailable", "Queries the server to determine the amount of data available."),
        func.create("InternetReadFile", "Reads data from a handle opened by the InternetOpenUrl, FtpOpenFile, or HttpOpenRequest function."),
    ].to_vec();
    dlls.insert("wininet.dll".to_string(), funcs);

    // ws2_32.dll
    let funcs: Vec<Func> = [
        func.create("wsaasyncgethostbyname", "Asynchronously retrieves host information that corresponds to a hostname."),
        func.create("getprofileinta", "Retrieves an integer from a key in the specified section of the Win.ini file."),
        func.create("inet_addr", "Converts a string containing an IPv4 dotted-decimal address into a proper address for the IN_ADDR structure."),
    ].to_vec();
    dlls.insert("ws2_32.dll".to_string(), funcs);

    // ELF

    // libc – core system calls & memory ops
    let funcs_libc: Vec<Func> = [
        func.create("dlopen", "Open a shared object and return a handle."),
        func.create("dlsym", "Look up a symbol in the shared object referenced by a handle."),
        func.create("dlclose", "Close a shared object opened with dlopen."),
        func.create("_dl_iterate_phdr", "Iterate over program headers of loaded modules (used for introspection)."),
        func.create("mprotect", "Change protection on memory pages – often used in exploits."),
        func.create("execve", "Execute a program, replacing the current process image."),
        func.create("ptrace", "Trace and manipulate other processes – key forensic indicator."),
    ].to_vec();
    dlls.insert("libc.so.6".to_string(), funcs_libc);

    // libdl – dynamic linking helpers
    let funcs_libdl: Vec<Func> = [
        func.create("__libc_dlerror", "Return error message from last dl* call."),
        func.create("__libc_dlopen_mode", "Internal helper for dlopen with mode flags."),
    ].to_vec();
    dlls.insert("libdl.so.2".to_string(), funcs_libdl);

    // libpthread – threading primitives
    let funcs_pthread: Vec<Func> = [
        func.create("pthread_create", "Create a new thread."),
        func.create("pthread_join", "Wait for a thread to terminate."),
        func.create("pthread_mutex_lock", "Lock a mutex."),
        func.create("pthread_mutex_unlock", "Unlock a mutex."),
        func.create("pthread_cond_wait", "Wait on a condition variable."),
    ].to_vec();
    dlls.insert("libpthread.so.0".to_string(), funcs_pthread);

    // libcrypto – cryptographic primitives
    let funcs_crypto: Vec<Func> = [
        func.create("EVP_encrypt_init_ex", "Initialize encryption context (OpenSSL)."),
        func.create("EVP_decrypt_update", "Decrypt data chunk (OpenSSL)."),
        func.create("RAND_bytes", "Generate random bytes (OpenSSL)."),
    ].to_vec();
    dlls.insert("libcrypto.so.1.1".to_string(), funcs_crypto);

    // libm – math functions that can be abused
    let funcs_math: Vec<Func> = [
        func.create("__ieee754_sqrt", "Square root implementation."),
        func.create("__pow10f", "Compute 10^x for float."),
    ].to_vec();
    dlls.insert("libm.so.6".to_string(), funcs_math);

    return dlls
}