extern crate serde; // needed for json serialization
extern crate serde_json; // needed for json serialization
extern crate whoami;

use chrono::{DateTime, Utc};
use is_elevated::is_elevated;
use serde::Serialize;
use std::collections::HashMap;
use std::{io, time::SystemTime};

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
    "application/x-java-archive",
    "application/x-jar",
    "application/vnd.android.package-archive",
    "application/x-ms-wizard",
    "application/x-ms-application",
    "application/x-dynamic-link-library",
    "application/x-executable",
    "application/x-mac-package",
    "application/x-mach-o",
    "application/x-pkcs7-cert",
    "application/x-pkcs12",
    "application/x-rpm",
    "application/x-debian-package",
    "application/x-tar",
    "application/x-gtar",
    "application/x-iso9660-image",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
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
    X86,     // 32-bit Intel/AMD
    X86_64,  // 64-bit Intel/AMD
    Arm,     // 32-bit ARM
    AArch64, // 64-bit ARM (sometimes called ARM64)
    Mips,
    PowerPC,
    RiscV,
    Itanium, // IA-64
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
trait Loggable: Serialize {
    /// convert struct to json
    fn to_log(self: &'_ Self) -> Str {
        ::serde_json::to_string(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }
    fn to_pretty_log(self: &'_ Self) -> Str {
        ::serde_json::to_string_pretty(&self)
            .ok()
            .map_or("<failed to serialize>".into(), Into::into)
    }

    // convert struct to json and report it out
    fn write_log(self: &'_ Self) {
        println!("{}", self.to_log());
    }
    fn write_pretty_log(self: &'_ Self) {
        println!("{}", self.to_pretty_log());
    }
}
impl<T: ?Sized + Serialize> Loggable for T {}

impl Default for ImpHashes {
    fn default() -> ImpHashes {
        ImpHashes {
            md5: String::new(),
            md5_sorted: String::new(),
            ssdeep: String::new(),
            ssdeep_sorted: String::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct ImpHashes {
    pub md5: String,
    pub md5_sorted: String,
    pub ssdeep: String,
    pub ssdeep_sorted: String,
}

impl Default for ExpHashes {
    fn default() -> ExpHashes {
        ExpHashes {
            md5: String::new(),
            md5_sorted: String::new(),
            ssdeep: String::new(),
            ssdeep_sorted: String::new(),
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
            info: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Function {
    pub name: String,
    pub info: String,
}

impl Default for Import {
    fn default() -> Import {
        Import {
            lib: String::new(),
            count: 0,
            names: Vec::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Import {
    pub lib: String,
    pub count: u32,
    pub names: Vec<Function>,
}

impl Default for Imports {
    fn default() -> Imports {
        Imports {
            hashes: ImpHashes::default(),
            lib_count: 0,
            func_count: 0,
            imports: Vec::new(),
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
    fn default() -> FileTimestamps {
        FileTimestamps {
            access_fn: String::new(),
            access_si: String::new(),
            create_fn: String::new(),
            create_si: String::new(),
            modify_fn: String::new(),
            modify_si: String::new(),
            mft_record: String::new(),
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
    pub mft_record: String,
}

impl Default for PeTimestamps {
    fn default() -> PeTimestamps {
        PeTimestamps {
            compile: String::new(),
            debug: String::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeTimestamps {
    pub compile: String,
    pub debug: String,
}

impl Default for PeLinker {
    fn default() -> PeLinker {
        PeLinker {
            major_version: 0,
            minor_version: 0,
        }
    }
}
#[derive(Serialize, Clone)]
pub struct PeLinker {
    pub major_version: u8,
    pub minor_version: u8,
}

impl Default for PeInfo {
    fn default() -> PeInfo {
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
    fn default() -> ElfInfo {
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
    fn default() -> MachOInfo {
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
    fn default() -> BinaryInfo {
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
    pub macho_info: MachOInfo,
    pub pe_info: PeInfo,
}

impl Default for BinSection {
    fn default() -> BinSection {
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
    fn default() -> BinSections {
        BinSections {
            total_sections: 0,
            total_raw_bytes: 0,
            total_virt_bytes: 0,
            sections: Vec::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct BinSections {
    pub total_sections: u16,
    pub total_raw_bytes: u32,
    pub total_virt_bytes: u32,
    pub sections: Vec<BinSection>,
}

impl Default for Exports {
    fn default() -> Exports {
        Exports {
            hashes: ExpHashes::default(),
            count: 0,
            names: Vec::new(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Exports {
    pub hashes: ExpHashes,
    pub count: usize,
    pub names: Vec<String>,
}

impl Default for Binary {
    fn default() -> Binary {
        Binary {
            binary_info: BinaryInfo::default(),
            sections: BinSections::default(),
            imports: Imports::default(),
            exports: Exports::default(),
        }
    }
}
#[derive(Serialize, Clone)]
pub struct Binary {
    pub binary_info: BinaryInfo,
    pub sections: BinSections,
    pub imports: Imports,
    pub exports: Exports,
}

impl Default for Hashes {
    fn default() -> Hashes {
        Hashes {
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
            ssdeep: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub ssdeep: String,
}

impl Default for DataRun {
    fn default() -> DataRun {
        DataRun {
            name: String::new(),
            bytes: 0,
            first_256_bytes: String::new(),
        }
    }
}
#[derive(Serialize, Clone, Debug)]
pub struct DataRun {
    pub name: String,
    pub bytes: u64,
    pub first_256_bytes: String,
}

impl Default for Link {
    fn default() -> Link {
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
    fn default() -> RunTimeEnv {
        RunTimeEnv {
            timestamp: get_time_iso8601().unwrap_or("1970-01-01T02:00:00+02:00Z".to_owned()),
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
    pub strings: Vec<String>,
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
        strings: Vec<String>,
    ) -> MetaData {
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
            strings,
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

pub fn is_function_interesting(dll: &str, func: &str) -> String {
    if DLLS.contains_key(dll) {
        let funcs = match DLLS.get(dll) {
            Some(it) => it,
            None => return String::new(),
        };
        for f in funcs {
            if f.name.to_lowercase().eq(&func.to_lowercase()) {
                return f.desc.clone();
            }
        }
    }
    String::new()
}

/*
    Information to include on interesting binary imported functions
    Research by Jason Langston
*/
impl Default for Func {
    fn default() -> Func {
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
    pub fn new(name: String, desc: String) -> Func {
        Func { name, desc }
    }

    pub fn create(&self, name: &str, desc: &str) -> Func {
        Func::new(name.to_string(), desc.to_string())
    }
}

pub fn build_interesting_funcs() -> HashMap<String, Vec<Func>> {
    let func = Func::default();
    let mut dlls: HashMap<String, Vec<Func>> = HashMap::new();

    // PE

    // advapi32.dll - Advanced Windows API (services, registry, users)
    let funcs: Vec<Func> = [
        func.create("accept", "Permits an incoming connection attempt on a socket."),
        func.create("connectnamedpipe", "Enables a named pipe server process to wait for a client process to connect to an instance of a named pipe."),
        func.create("createfilew", "Creates or opens a file or I/O device. The most commonly used I/O devices are files, file streams, directories, physical disks, volumes, console buffers, tape drives, communications resources, mailslots, and pipes."),
        func.create("createmutexa", "Creates or opens a named or unnamed mutex object."),
        func.create("createprocessa", "Creates a new process and its primary thread. The new process runs in the security context of the calling process."),
        func.create("createprocessw", "Creates a new process and its primary thread. The new process runs in the security context of the calling process. This is the Unicode version of CreateProcessA."),
        func.create("regopenkeyexa", "Opens a registry key with specified access rights."),
        func.create("regqueryvalueexa", "Queries information about a registry value."),
        func.create("gettokeninformation", "Retrieves information about a token, including user privileges and group memberships."),
        func.create("openprocesstoken", "Opens the primary token of a process for use by the calling thread."),
        func.create("CreateProcessAsUserA", "Creates a new process in the security context of a specific user."),
        func.create("CreateProcessAsUserW", "Creates a new process in the security context of a specific user (Unicode)."),
        func.create("RegCreateKeyExA", "Creates a registry key."),
        func.create("RegSetValueExA", "Sets the value of a registry key."),
        func.create("OpenSCManagerA", "Opens the service control manager."),
        func.create("CreateServiceA", "Creates a service."),
        func.create("StartServiceA", "Starts a service."),
        func.create("CryptSetHashParam", "Customizes the operations of a hash object."),
        func.create("CryptGetHashParam", "Retrieves data that governs the operations of a hash object."),
        func.create("CryptExportKey", "Exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner."),
        func.create("CryptAcquireContextW", "Acquires a handle to a particular key container within a particular cryptographic service provider (CSP). This is the Unicode version."),
        func.create("CryptSetKeyParam", "Customizes various aspects of a key's operations."),
        func.create("CryptGetKeyParam", "Retrieves data that governs the operations of a key."),
        func.create("CryptReleaseContext", "Releases the handle of a cryptographic service provider (CSP) and a key container."),
        func.create("CryptDuplicateKey", "Creates a duplicate of a cryptographic key."),
        func.create("CryptAcquireContextA", "Acquires a handle to a particular key container within a particular cryptographic service provider (CSP). This is the ANSI version."),
        func.create("CryptGetProvParam", "Retrieves parameters that govern the operations of a cryptographic service provider (CSP)."),
        func.create("CryptImportKey", "Transfers a cryptographic key from a key BLOB to a cryptographic service provider (CSP)."),
        func.create("SystemFunction007", "Undocumented function, likely related to cryptography."),
        func.create("CryptEncrypt", "Encrypts data."),
        func.create("CryptCreateHash", "Initiates the hashing of a stream of data."),
        func.create("CryptGenKey", "Generates a random cryptographic key or a key pair."),
        func.create("CryptDestroyKey", "Releases the handle to a cryptographic key."),
        func.create("CryptDecrypt", "Decrypts data that was previously encrypted."),
        func.create("CryptDestroyHash", "Destroys a hash object."),
        func.create("CryptHashData", "Adds data to a specified hash object."),
        func.create("CopySid", "Copies a security identifier (SID) to a buffer."),
        func.create("GetLengthSid", "Returns the length, in bytes, of a valid security identifier (SID)."),
        func.create("LsaQueryInformationPolicy", "Retrieves information about a Policy object."),
        func.create("LsaOpenPolicy", "Opens a handle to the Policy object on a local or remote system."),
        func.create("LsaClose", "Closes a handle to a Policy object."),
        func.create("CreateWellKnownSid", "Creates a SID for predefined aliases."),
        func.create("CreateProcessWithLogonW", "Creates a new process and its primary thread. The new process runs in the security context of the specified credentials."),
        func.create("RegQueryValueExW", "Retrieves the type and data for a specified value name associated with an open registry key. This is the Unicode version."),
        func.create("RegQueryInfoKeyW", "Retrieves information about a specified registry key. This is the Unicode version."),
        func.create("RegEnumValueW", "Enumerates the values for the specified open registry key. This is the Unicode version."),
        func.create("RegOpenKeyExW", "Opens a specified registry key. This is the Unicode version."),
        func.create("RegEnumKeyExW", "Enumerates the subkeys of the specified open registry key. This is the Unicode version."),
        func.create("RegCloseKey", "Closes a handle to a specified registry key."),
        func.create("RegSetValueExW", "Sets the data and type of a specified value under a registry key. This is the Unicode version."),
        func.create("SystemFunction032", "Undocumented function, likely related to cryptography."),
        func.create("ConvertSidToStringSidW", "Converts a security identifier (SID) to a string format suitable for display, storage, or transmission."),
        func.create("CreateServiceW", "Creates a service object and adds it to the specified service control manager database. This is the Unicode version."),
        func.create("CloseServiceHandle", "Closes a handle to a service control manager or service object."),
        func.create("DeleteService", "Marks a service for deletion from the service control manager database."),
        func.create("OpenSCManagerW", "Establishes a connection to the service control manager on the specified computer and opens the specified service control manager database. This is the Unicode version."),
        func.create("SetServiceObjectSecurity", "Sets the security descriptor of a service object."),
        func.create("OpenServiceW", "Opens an existing service. This is the Unicode version."),
        func.create("BuildSecurityDescriptorW", "Allocates and initializes a new security descriptor. This is the Unicode version."),
        func.create("QueryServiceObjectSecurity", "Retrieves the security descriptor associated with a service object."),
        func.create("StartServiceW", "Starts a service. This is the Unicode version."),
        func.create("AllocateAndInitializeSid", "Allocates and initializes a security identifier (SID) with up to eight subauthorities."),
        func.create("QueryServiceStatusEx", "Retrieves the current status of the specified service based on the specified information level."),
        func.create("FreeSid", "Frees a security identifier (SID) previously allocated by using the AllocateAndInitializeSid function."),
        func.create("ControlService", "Sends a control code to a service."),
        func.create("IsTextUnicode", "Determines whether a buffer of text is likely to be Unicode."),
        func.create("LookupAccountNameW", "Retrieves a security identifier (SID) for the specified account name. This is the Unicode version."),
        func.create("LookupAccountSidW", "Retrieves the name of the account for a specified SID. This is the Unicode version."),
        func.create("DuplicateTokenEx", "Creates a new access token that duplicates an existing token."),
        func.create("CheckTokenMembership", "Determines whether a specified security identifier (SID) is enabled in an access token."),
        func.create("CryptSetProvParam", "Sets parameters for a cryptographic service provider (CSP)."),
        func.create("CryptEnumProvidersW", "Retrieves the available cryptographic service providers (CSPs). This is the Unicode version."),
        func.create("ConvertStringSidToSidW", "Converts a string-format security identifier (SID) into a valid, functional SID."),
        func.create("LsaFreeMemory", "Frees memory allocated by an LSA function."),
        func.create("GetSidSubAuthority", "Retrieves a pointer to a specified subauthority in a security identifier (SID)."),
        func.create("GetSidSubAuthorityCount", "Retrieves a pointer to the subauthority count field of a security identifier (SID)."),
        func.create("IsValidSid", "Validates a security identifier (SID) by verifying that the revision number is within a known range, and that the number of subauthorities is less than the maximum."),
        func.create("SetThreadToken", "Assigns an impersonation token to a thread."),
        func.create("CryptEnumProviderTypesW", "Retrieves the types of cryptographic service providers (CSPs) available on the computer. This is the Unicode version."),
        func.create("SystemFunction006", "Undocumented function, likely related to cryptography."),
        func.create("CryptGetUserKey", "Retrieves a handle to one of a user's public/private key pairs."),
        func.create("OpenEventLogW", "Opens a handle to the specified event log. This is the Unicode version."),
        func.create("GetNumberOfEventLogRecords", "Retrieves the number of records in the specified event log."),
        func.create("ClearEventLogW", "Clears the specified event log, and optionally saves the current copy of the log to a backup file."),
        func.create("SystemFunction001", "Undocumented function, likely related to cryptography."),
        func.create("CryptDeriveKey", "Generates a cryptographic session key derived from a base data value."),
        func.create("SystemFunction005", "Undocumented function, likely related to cryptography."),
        func.create("LsaQueryTrustedDomainInfoByName", "Retrieves information about a trusted domain."),
        func.create("CryptSignHashW", "Signs a hash object. This is the Unicode version."),
        func.create("LsaOpenSecret", "Opens a secret object."),
        func.create("LsaQuerySecret", "Retrieves a secret object from the LSA database."),
        func.create("SystemFunction013", "Undocumented function, likely related to cryptography."),
        func.create("LsaRetrievePrivateData", "Retrieves a private data value from a secret object."),
        func.create("LsaEnumerateTrustedDomainsEx", "Enumerates trusted domains."),
        func.create("LookupPrivilegeValueW", "Retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name."),
        func.create("StartServiceCtrlDispatcherW", "Connects the main thread of a service process to the service control manager, which causes the thread to be the service control dispatcher thread for the calling process."),
        func.create("SetServiceStatus", "Updates the service control manager about the current status of a service."),
        func.create("RegisterServiceCtrlHandlerW", "Registers a function to handle service control requests."),
        func.create("LookupPrivilegeNameW", "Retrieves the name of the privilege represented by a specified locally unique identifier (LUID)."),
        func.create("OpenThreadToken", "Opens the access token associated with a thread."),
        func.create("CredFree", "Frees a credential buffer."),
        func.create("CredEnumerateW", "Enumerates credentials from the user's credential set."),
        func.create("SystemFunction025", "Undocumented function, likely related to cryptography."),
        func.create("ConvertStringSecurityDescriptorToSecurityDescriptorW", "Converts a string-format security descriptor into a valid, functional security descriptor."),
        func.create("SystemFunction024", "Undocumented function, likely related to cryptography."),
        func.create("CredIsMarshaledCredentialW", "Determines if a specified credential is a marshaled credential."),
        func.create("CredUnmarshalCredentialW", "Unmarshals a credential."),
        func.create("A_SHAFinal", "Finishes a SHA hash."),
        func.create("A_SHAInit", "Initializes a SHA hash."),
        func.create("A_SHAUpdate", "Updates a SHA hash."),
    ].to_vec();
    dlls.insert("advapi32.dll".to_string(), funcs);

    // comdlg32.dll - Common Dialogs API
    let funcs: Vec<Func> = [
        func.create("choosefonta", "Displays a font selection dialog box."),
        func.create("choosecolora", "Displays a color selection dialog box."),
    ]
    .to_vec();
    dlls.insert("comdlg32.dll".to_string(), funcs);

    // crypt32.dll - Cryptography API
    let funcs: Vec<Func> = [
        func.create(
            "bitblt",
            "Performs a bit-block transfer of color data from one device context to another.",
        ),
        func.create(
            "certopensystemstorea",
            "Opens the most common system certificate store using ANSI character encoding.",
        ),
        func.create("CertFindCertificateInStore", "Finds the first or next certificate context in a certificate store that matches a search criterion."),
        func.create("CertEnumSystemStore", "Retrieves the system stores."),
        func.create("CertEnumCertificatesInStore", "Retrieves the first or next certificate in a certificate store."),
        func.create("CertAddCertificateContextToStore", "Adds a certificate context to a certificate store."),
        func.create("CryptDecodeObjectEx", "Decodes a certificate, certificate revocation list (CRL), certificate trust list (CTL), or key."),
        func.create("CertAddEncodedCertificateToStore", "Adds an encoded certificate to a certificate store."),
        func.create("CertOpenStore", "Opens a certificate store."),
        func.create("CertFreeCertificateContext", "Frees a certificate context."),
        func.create("CertCloseStore", "Closes a certificate store handle."),
        func.create("CertSetCertificateContextProperty", "Sets a property for a certificate context."),
        func.create("PFXExportCertStoreEx", "Exports a certificate store to a PFX BLOB."),
        func.create("CryptUnprotectData", "Decrypts and does an integrity check of data."),
        func.create("CryptBinaryToStringW", "Converts a byte array to a string. This is the Unicode version."),
        func.create("CryptBinaryToStringA", "Converts a byte array to a string. This is the ANSI version."),
        func.create("CryptStringToBinaryW", "Converts a string to a byte array. This is the Unicode version."),
        func.create("CryptExportPublicKeyInfo", "Exports the public key information associated with the corresponding private key of the provider."),
        func.create("CryptFindOIDInfo", "Finds the specified object identifier (OID) information."),
        func.create("CryptAcquireCertificatePrivateKey", "Acquires the private key for a certificate."),
        func.create("CertNameToStrW", "Converts a certificate name to a null-terminated string. This is the Unicode version."),
        func.create("CryptStringToBinaryA", "Converts a string to a byte array. This is the ANSI version."),
        func.create("CertGetCertificateContextProperty", "Retrieves a property from a certificate context."),
        func.create("CryptSignAndEncodeCertificate", "Signs and encodes a certificate."),
        func.create("CryptEncodeObject", "Encodes a structure of the type indicated by the value of the lpszStructType parameter."),
        func.create("CryptProtectData", "Performs encryption on the data in a DATA_BLOB structure."),
        func.create("CryptQueryObject", "Retrieves information about the contents of a cryptographic object."),
        func.create("CertGetNameStringW", "Retrieves the name of a certificate subject or issuer. This is the Unicode version."),
    ]
    .to_vec();
    dlls.insert("crypt32.dll".to_string(), funcs);

    // gdi32.dll - Graphics Device Interface API

    let funcs: Vec<Func> =
        [func.create("bind", "Associates a local address with a socket.")].to_vec();
    dlls.insert("gdi32.dll".to_string(), funcs);

    // icmp.dll - Internet Control Message Protocol API
    let funcs: Vec<Func> = [func.create(
        "IcmpCreateFile",
        "Opens a handle on which IPv4 ICMP echo requests can be issued.",
    )]
    .to_vec();
    dlls.insert("icmp.dll".to_string(), funcs);

    // kernel32.dll - Core system functions (memory, processes, threads)
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
        func.create("createthread", "Creates a new thread in the current process."),
        func.create("waitforsingleobject", "Waits for an object to be signaled."),
        func.create("readfile", "Reads data from a file handle."),
        func.create("writefile", "Writes data to a file handle."),
        func.create("closehandle", "Closes handles opened with CreateFile or similar functions."),
        func.create("addvectoredexceptionhandler", "Adds a vectored exception handler to the process."),
        func.create("createfilemappinga", "Creates or opens a named or unnamed file mapping object for a specified file. This is the ANSI version."),
        func.create("createfilew", "Creates or opens a file or I/O device with Unicode characters."),
        func.create("createtoolhelp32snapshot", "Takes a snapshot of the specified processes, heaps, modules, and threads used by the system."),
        func.create("duplicatehandle", "Duplicates an object handle for use in another process."),
        func.create("exitprocess", "Terminates the calling process."),
        func.create("findclose", "Closes a search handle opened with FindFirstFile."),
        func.create("findfirstfileexw", "Searches a directory for a file or subdirectory with a name and attributes that match those specified. This is the Unicode version."),
        func.create("findnextfilew", "Continues a file search from a previous call to the FindFirstFile, FindFirstFileEx, or FindFirstFileTransacted function. This is the Unicode version."),
        func.create("formatmessagew", "Formats a message string using the specified parameters."),
        func.create("freelibrary", "Frees a loaded dynamic-link library (DLL)."),
        func.create("getcommandlinew", "Retrieves the command line for the current process."),
        func.create("getconsolemode", "Retrieves the console mode of the specified console output handle."),
        func.create("getconsoleoutputcp", "Retrieves the code page used by the console output handle."),
        func.create("getcurrentdirectoryw", "Retrieves the current directory path for the calling process."),
        func.create("getcurrentprocess", "Returns a handle to the current process."),
        func.create("getcurrentthread", "Returns a handle to the current thread."),
        func.create("getenvironmentvariablew", "Retrieves the value of an environment variable."),
        func.create("getfileinformationbyhandle", "Retrieves information about a file from its handle."),
        func.create("getfileinformationbyhandleex", "Retrieves extended information about a file from its handle."),
        func.create("getfinalpathnamebyhandlew", "Retrieves the final path of a file by its handle."),
        func.create("getfullpathnamew", "Retrieves the full path name for a specified file."),
        func.create("getlasterror", "Retrieves the last error that occurred in the calling thread."),
        func.create("getmodulefilenamew", "Retrieves the fully qualified path for the file that contains the specified module. The module must have been loaded by the current process. This is the Unicode version."),
        func.create("getmodulehandlea", "Retrieves a module handle for the specified module. The module must have been loaded by the calling process. This is the ANSI version."),
        func.create("getmodulehandlew", "Retrieves a module handle for the specified module. The module must have been loaded by the calling process. This is the Unicode version."),
        func.create("getprocaddress", "Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL)."),
        func.create("getprocessheap", "Returns a handle to the heap used by the current process."),
        func.create("getstdhandle", "Retrieves a handle to the standard input, output, or error device for the calling process."),
        func.create("getsystimepreciseasfiletime", "Retrieves the system time with high precision and converts it to file time format."),
        func.create("heapalloc", "Allocates memory from the heap."),
        func.create("heapfree", "Frees memory allocated by HeapAlloc or HeapReAlloc."),
        func.create("heaprealloc", "Reallocates memory in the heap."),
        func.create("initoncebegininitialize", "Initializes a once-only initialization object."),
        func.create("initoncecomplete", "Completes an initialization of a once-only initialization object."),
        func.create("loadlibraryexw", "Loads the specified module into the address space of the calling process, with additional control over loading behavior. This is the Unicode version."),
        func.create("mapviewoffile", "Maps a view of a file in memory."),
        func.create("module32firstw", "Retrieves information about the first module in the specified process."),
        func.create("module32nextw", "Retrieves information about the next module in the specified process."),
        func.create("multbytetowidechar", "Converts a multibyte string to a wide-character string."),
        func.create("rtlcapturecontext", "Captures the current execution context of the calling thread."),
        func.create("rtllookupfunctionentry", "Looks up a function entry in a stack frame."),
        func.create("rtlvirtualunwind", "Performs virtual unwinding of a stack frame."),
        func.create("setfileinformationbyhandle", "Sets information about a file using its handle."),
        func.create("setfilepointerex", "Sets the file pointer to the specified offset and returns the new position."),
        func.create("setlasterror", "Sets the last error that occurred in the calling thread."),
        func.create("setthreadstackguarantee", "Sets the minimum stack size guaranteed for a thread."),
        func.create("setunhandledexceptionfilter", "Sets the unhandled exception filter for the process."),
        func.create("sleep", "Suspends execution of the calling thread for the specified interval."),
        func.create("tlsalloc", "Allocates a TLS index."),
        func.create("tlsfree", "Frees a TLS index."),
        func.create("tlsgetvalue", "Retrieves the value associated with a TLS index."),
        func.create("tlssetvalue", "Sets the value associated with a TLS index."),
        func.create("unmapviewoffile", "Unmaps a view of a file from memory."),
        func.create("waitforsingleobject", "Waits for an object to be signaled."),
        func.create("writeconsolew", "Writes data to the console output handle."),
        func.create("deletecriticalsection", "Deletes a critical section object."),
        func.create("entercriticalsection", "Enters a critical section."),
        func.create("initializecriticalsection", "Initializes a critical section object."),
        func.create("leavecriticalsection", "Leaves a critical section."),
        func.create("raiseexception", "Raises an exception in the calling thread."),
        func.create("rtlvirtualunwindex", "Performs virtual unwinding of a stack frame with additional parameters."),
        func.create("virtualprotect", "Changes the protection on memory pages."),
        func.create("virtualquery", "Retrieves information about a region of memory."),
        func.create("__cspecific_handler", "Internal handler for structured exception handling."),
        func.create("CompareStringW", "Compares two character strings, for a locale specified by identifier."),
        func.create("LCMapStringW", "Maps a character string to another, performing a specified transformation."),
        func.create("GetSystemTimePreciseAsFileTime", "Retrieves the current system date and time with the highest possible level of precision (<1us). The retrieved information is in Coordinated Universal Time (UTC) format."),
        func.create("WaitForSingleObjectEx", "Waits for an object to be signaled, with a timeout and an alertable option."),
        func.create("lstrlenW", "Returns the length of a string in characters (not including the terminating null character)."),
        func.create("GetCurrentProcessId", "Retrieves the process identifier of the calling process."),
        func.create("CreateMutexA", "Creates or opens a named or unnamed mutex object."),
        func.create("WideCharToMultiByte", "Maps a UTF-16 (wide character) string to a new character string."),
        func.create("ReleaseMutex", "Releases ownership of the specified mutex object."),
        func.create("MultiByteToWideChar", "Maps a character string to a UTF-16 (wide character) string."),
        func.create("FlsFree", "Releases a fiber local storage (FLS) index, making it available for reuse."),
        func.create("FlushFileBuffers", "Flushes the buffers of a specified file and causes all buffered data to be written to a file."),
        func.create("QueryPerformanceCounter", "Retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp that can be used for time-interval measurements."),
        func.create("GetCurrentThreadId", "Retrieves the thread identifier of the calling thread."),
        func.create("GetSystemTimeAsFileTime", "Retrieves the current system date and time. The information is in Coordinated Universal Time (UTC) format."),
        func.create("InitializeSListHead", "Initializes the head of a singly linked list."),
        func.create("IsDebuggerPresent", "Determines whether the calling process is being debugged by a user-mode debugger."),
        func.create("UnhandledExceptionFilter", "Passes unhandled exceptions to the debugger, if the process is being debugged. Otherwise, it optionally displays an Application Error message box and executes the associated exception handlers."),
        func.create("IsProcessorFeaturePresent", "Determines whether the specified processor feature is supported by the current computer."),
        func.create("RtlUnwindEx", "Initiates an unwind of procedure call frames."),
        func.create("EncodePointer", "Encodes a pointer. This is used to provide another layer of protection against pointer overwrites."),
        func.create("InitializeCriticalSectionAndSpinCount", "Initializes a critical section object and sets the spin count for the critical section."),
        func.create("RtlPcToFileHeader", "Retrieves the base address of the image that contains the specified PC value."),
        func.create("TerminateProcess", "Terminates the specified process and all of its threads."),
        func.create("GetCommandLineA", "Retrieves the command-line string for the current process."),
        func.create("IsValidCodePage", "Determines if a specified code page is valid."),
        func.create("GetACP", "Retrieves the current ANSI code page identifier for the operating system."),
        func.create("GetOEMCP", "Retrieves the current original equipment manufacturer (OEM) code page identifier for the operating system."),
        func.create("GetCPInfo", "Retrieves information about any valid installed or available code page."),
        func.create("GetEnvironmentStringsW", "Retrieves the environment block for the current process."),
        func.create("FreeEnvironmentStringsW", "Frees a block of environment strings."),
        func.create("SetEnvironmentVariableW", "Sets the value of an environment variable for the current process."),
        func.create("SetStdHandle", "Sets the handle for the standard input, standard output, or standard error device."),
        func.create("GetFileType", "Retrieves the file type of the specified file."),
        func.create("GetStringTypeW", "Retrieves character type information for the characters in a specified Unicode string."),
        func.create("FlsAlloc", "Allocates a fiber local storage (FLS) index."),
        func.create("FlsGetValue", "Retrieves the value in the calling fiber's fiber local storage (FLS) slot for a specified FLS index."),
        func.create("FlsSetValue", "Stores a value in the calling fiber's fiber local storage (FLS) slot for a specified FLS index."),
        func.create("HeapSize", "Retrieves the size of a memory block allocated from a heap by HeapAlloc or HeapReAlloc."),
        func.create("GetFullPathNameA", "Retrieves the full path and file name of the specified file. This is the ANSI version."),
        func.create("GetTimeFormatW", "Formats time as a time string for a locale specified by identifier. This is the Unicode version."),
        func.create("SystemTimeToFileTime", "Converts a system time to a file time."),
        func.create("GetDateFormatW", "Formats a date as a date string for a locale specified by the identifier. This is the Unicode version."),
        func.create("PurgeComm", "Discards all characters from the output or input buffer of a specified communications resource."),
        func.create("ClearCommError", "Retrieves information about a communications error and reports the current status of a communications device."),
        func.create("GetProcessId", "Retrieves the process identifier of the specified process."),
        func.create("SetConsoleOutputCP", "Sets the output code page used by the console associated with the calling process."),
        func.create("WriteProcessMemory", "Writes data to an area of memory in a specified process."),
        func.create("VirtualProtectEx", "Changes the protection on a region of committed pages in the virtual address space of a specified process."),
        func.create("VirtualAlloc", "Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process."),
        func.create("ReadProcessMemory", "Reads data from an area of memory in a specified process."),
        func.create("VirtualFreeEx", "Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process."),
        func.create("VirtualQueryEx", "Retrieves information about a range of pages in the virtual address space of a specified process."),
        func.create("VirtualFree", "Releases, decommits, or releases and decommits a region of pages within the virtual address space of the calling process."),
        func.create("GetComputerNameExW", "Retrieves a NetBIOS or DNS name associated with the local computer. This is the Unicode version."),
        func.create("OpenProcess", "Opens an existing local process object."),
        func.create("ExpandEnvironmentStringsW", "Expands environment-variable strings and replaces them with the values defined for the current user. This is the Unicode version."),
        func.create("GetFileSizeEx", "Retrieves the size of the specified file."),
        func.create("GetFileAttributesW", "Retrieves file system attributes for a specified file or directory. This is the Unicode version."),
        func.create("DeleteFileA", "Deletes an existing file. This is the ANSI version."),
        func.create("FileTimeToLocalFileTime", "Converts a file time to a local file time."),
        func.create("GetCurrentDirectoryA", "Retrieves the current directory for the current process. This is the ANSI version."),
        func.create("GetTempFileNameA", "Creates a name for a temporary file. This is the ANSI version."),
        func.create("SetFilePointer", "Moves the file pointer of an open file."),
        func.create("FileTimeToDosDateTime", "Converts a file time to MS-DOS date and time values."),
        func.create("LocalFree", "Frees the specified local memory object and invalidates its handle."),
        func.create("LocalAlloc", "Allocates the specified number of bytes from the heap."),
        func.create("TerminateThread", "Terminates a thread."),
        func.create("FileTimeToSystemTime", "Converts a file time to system time format."),
        func.create("HeapCompact", "Attempts to compact the specified heap."),
        func.create("SetEndOfFile", "Sets the physical file size for the specified file to the current position of the file pointer."),
        func.create("UnlockFile", "Unlocks a region in an open file."),
        func.create("FlushViewOfFile", "Writes to the disk a byte range within a mapped view of a file."),
        func.create("LockFile", "Locks a region in an open file."),
        func.create("OutputDebugStringW", "Sends a string to the debugger for display. This is the Unicode version."),
        func.create("GetTickCount", "Retrieves the number of milliseconds that have elapsed since the system was started."),
        func.create("UnlockFileEx", "Unlocks a region in the specified file."),
        func.create("FormatMessageA", "Formats a message string. This is the ANSI version."),
        func.create("GetFileSize", "Retrieves the size of the specified file, in bytes."),
        func.create("HeapDestroy", "Destroys the specified heap object."),
        func.create("GetFileAttributesA", "Retrieves file system attributes for a specified file or directory. This is the ANSI version."),
        func.create("HeapCreate", "Creates a private heap object that can be used by the calling process."),
        func.create("HeapValidate", "Validates the specified heap."),
        func.create("LockFileEx", "Locks the specified file for exclusive access by the calling process."),
        func.create("GetDiskFreeSpaceW", "Retrieves information about the specified disk, including the amount of free space on the disk. This is the Unicode version."),
        func.create("GetDiskFreeSpaceA", "Retrieves information about the specified disk, including the amount of free space on the disk. This is the ANSI version."),
        func.create("GetSystemInfo", "Retrieves information about the current system."),
        func.create("GetFileAttributesExW", "Retrieves attributes for a specified file or directory. This is the Unicode version."),
        func.create("OutputDebugStringA", "Sends a string to the debugger for display. This is the ANSI version."),
        func.create("DeleteFileW", "Deletes an existing file. This is the Unicode version."),
        func.create("GetSystemTime", "Retrieves the current system date and time in Coordinated Universal Time (UTC)."),
        func.create("AreFileApisANSI", "Determines whether the file I/O functions are using the ANSI or OEM character set code page."),
        func.create("SetConsoleCtrlHandler", "Adds or removes an application-defined HandlerRoutine function from the list of handler functions for the calling process."),
        func.create("SetConsoleTitleW", "Sets the title for the current console window. This is the Unicode version."),
        func.create("lstrlenA", "Determines the length of the specified string (not including the terminating null character). This is the ANSI version."),
        func.create("GlobalSize", "Retrieves the current size of the specified global memory object, in bytes."),
        func.create("SetHandleInformation", "Sets certain properties of an object handle."),
        func.create("CreatePipe", "Creates an anonymous pipe, and returns handles to the read and write ends of the pipe."),
        func.create("SetEvent", "Sets the specified event object to the signaled state."),
        func.create("CreateEventW", "Creates or opens a named or unnamed event object. This is the Unicode version."),
        func.create("GetSystemDirectoryW", "Retrieves the path of the system directory. This is the Unicode version."),
        func.create("SetConsoleCursorPosition", "Sets the cursor position in the specified console screen buffer."),
        func.create("GetTimeZoneInformation", "Retrieves the current time zone settings."),
        func.create("FillConsoleOutputCharacterW", "Writes a character to the console screen buffer a specified number of times, beginning at the specified coordinates. This is the Unicode version."),
        func.create("GetConsoleScreenBufferInfo", "Retrieves information about the specified console screen buffer."),
        func.create("GetComputerNameW", "Retrieves the NetBIOS name of the local computer. This is the Unicode version."),
        func.create("ProcessIdToSessionId", "Retrieves the Remote Desktop Services session associated with a specified process."),
        func.create("SetCurrentDirectoryW", "Changes the current directory for the current process. This is the Unicode version."),
    ].to_vec();
    dlls.insert("kernel32.dll".to_string(), funcs);

    // mpr.dll - Multiple Provider Router API (network connections)
    let funcs: Vec<Func> = [
        func.create(
            "certopensystemstorew",
            "Opens the most common system certification store. This is the Unicode version.",
        ),
        func.create(
            "wnetuseconnectionw",
            "Makes a connection to a network resource. This is the Unicode version.",
        ),
    ]
    .to_vec();
    dlls.insert("mpr.dll".to_string(), funcs);

    // mscoree.dll - .NET Runtime Execution Engine

    let funcs: Vec<Func> =
        [func.create("controlservice", "Sends a control code to a service.")].to_vec();
    dlls.insert("mscoree.dll".to_string(), funcs);

    // netapi32.dll - Network API for administration
    let funcs: Vec<Func> = [
        func.create(
            "NetShareEnum",
            "Retrieves information about each shared resource on a server.",
        ),
        func.create(
            "NetWkstaGetInfo",
            "Returns information about the configuration of a workstation.",
        ),
        func.create(
            "netapi32",
            "Provides API functions for network administration.",
        ),
        func.create(
            "NetServerGetInfo",
            "Retrieves current operating parameters for a specified server.",
        ),
        func.create(
            "NetStatisticsGet",
            "Retrieves operating statistics for a service.",
        ),
        func.create(
            "DsEnumerateDomainTrustsW",
            "Enumerates the trust relationships for a specified domain.",
        ),
        func.create(
            "DsGetDcNameW",
            "Finds a domain controller in a specified domain.",
        ),
        func.create(
            "NetApiBufferFree",
            "Frees the memory that the NetApiBufferAllocate function allocates.",
        ),
        func.create(
            "NetRemoteTOD",
            "Retrieves the time of day from a remote server.",
        ),
        func.create(
            "NetSessionEnum",
            "Provides information about sessions established on a server.",
        ),
        func.create(
            "NetWkstaUserEnum",
            "Lists all users currently logged on to the workstation.",
        ),
        func.create(
            "I_NetServerAuthenticate2",
            "Authenticates a server application client.",
        ),
        func.create(
            "I_NetServerTrustPasswordsGet",
            "Gets the trusted domain password.",
        ),
        func.create(
            "I_NetServerReqChallenge",
            "Requests a challenge from a server.",
        ),
    ]
    .to_vec();
    dlls.insert("netapi32.dll".to_string(), funcs);

    // ntdll.dll - NT Layer DLL (low-level system functions)
    let funcs: Vec<Func> = [
        func.create("ntcreatefile", "Creates or opens a file or I/O device."),
        func.create(
            "ntqueryinformationfile",
            "Queries information about a file object.",
        ),
        func.create("ntreadfile", "Reads data from a file handle."),
        func.create("ntwritefile", "Writes data to a file handle."),
        func.create(
            "rtlntstatustodoserror",
            "Converts NT status code to DOS error code.",
        ),
        func.create(
            "NtCreateThreadEx",
            "A more powerful version of CreateRemoteThread.",
        ),
        func.create(
            "NtMapViewOfSection",
            "Maps a section object into the virtual address space of a process.",
        ),
        func.create("NtUnmapViewOfSection", "Unmaps a previously mapped view."),
        func.create("NtQueueApcThread", "Queues an APC to a thread."),
        func.create("NtResumeThread", "Resumes a suspended thread."),
        func.create("LdrLoadDll", "Loads a DLL."),
        func.create("RtlCreateUserThread", "Another way to create a thread."),
        func.create("RtlFreeAnsiString", "Frees the buffer for an ANSI string."),
        func.create("RtlDowncaseUnicodeString", "Converts a Unicode string to lowercase."),
        func.create("RtlFreeUnicodeString", "Frees the buffer for a Unicode string."),
        func.create("RtlInitUnicodeString", "Initializes a new Unicode string."),
        func.create("RtlEqualUnicodeString", "Compares two Unicode strings for equality."),
        func.create("NtQueryObject", "Retrieves various kinds of object information."),
        func.create("RtlCompressBuffer", "Compresses a buffer."),
        func.create("RtlGetCompressionWorkSpaceSize", "Calculates the size of the workspace required for compression."),
        func.create("NtQuerySystemInformation", "Retrieves the specified system information."),
        func.create("RtlGetCurrentPeb", "Retrieves a pointer to the Process Environment Block (PEB) of the current process."),
        func.create("NtQueryInformationProcess", "Retrieves information about the specified process."),
        func.create("RtlUnicodeStringToAnsiString", "Converts the specified Unicode source string into an ANSI destination string."),
        func.create("RtlGUIDFromString", "Converts a string representation of a GUID to a GUID."),
        func.create("RtlStringFromGUID", "Converts a GUID to its string representation."),
        func.create("NtCompareTokens", "Compares two tokens and determines if they are equal."),
        func.create("RtlGetNtVersionNumbers", "Retrieves the major and minor version numbers and the build number of the operating system."),
        func.create("RtlEqualString", "Compares two 8-bit strings."),
        func.create("RtlUpcaseUnicodeString", "Converts a Unicode string to uppercase."),
        func.create("RtlAppendUnicodeStringToString", "Appends a Unicode string to another."),
        func.create("RtlAnsiStringToUnicodeString", "Converts an ANSI string to a Unicode string."),
        func.create("RtlFreeOemString", "Frees the buffer for an OEM string."),
        func.create("RtlUpcaseUnicodeStringToOemString", "Converts a Unicode string to an uppercase OEM string."),
        func.create("NtResumeProcess", "Resumes a suspended process."),
        func.create("RtlAdjustPrivilege", "Enables or disables a privilege from the calling thread or process."),
        func.create("NtSuspendProcess", "Suspends the specified process."),
        func.create("NtTerminateProcess", "Terminates a process and all of its threads."),
        func.create("NtQuerySystemEnvironmentValueEx", "Queries the value of a system environment variable."),
        func.create("NtSetSystemEnvironmentValueEx", "Sets the value of a system environment variable."),
        func.create("NtEnumerateSystemEnvironmentValuesEx", "Enumerates system environment variables."),
        func.create("RtlIpv4AddressToStringW", "Converts an IPv4 address to a string in Internet standard dot-decimal format."),
        func.create("RtlIpv6AddressToStringW", "Converts an IPv6 address to a string in Internet standard format."),
    ]
    .to_vec();
    dlls.insert("ntdll.dll".to_string(), funcs);

    // oleaut32.dll - OLE Automation API
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
        func.create("CoInitialize", "Initializes the COM library for use by the current thread."),
        func.create("CoCreateInstance", "Creates an instance of a COM object."),
        func.create("ORDINAL 8", "Undocumented function."),
        func.create("ORDINAL 6", "Undocumented function."),
        func.create("ORDINAL 2", "Undocumented function."),
    ]
    .to_vec();
    dlls.insert("oleaut32.dll".to_string(), funcs);

    // psapi.dll - Process Status API
    let funcs: Vec<Func> = [
        func.create("EnumProcesses", "Enumerates processes."),
        func.create("EnumProcessModules", "Enumerates modules in a process."),
        func.create("GetModuleFileNameExA", "Retrieves the path of a module."),
        func.create(
            "GetModuleFileNameExW",
            "Retrieves the path of a module (Unicode).",
        ),
    ]
    .to_vec();
    dlls.insert("psapi.dll".to_string(), funcs);

    // rpcrt4.dll - Remote Procedure Call Runtime
    let funcs: Vec<Func> = [
        func.create(
            "AdjustTokenPrivileges",
            "Enables or disables privileges in the specified access token.",
        ),
        func.create("RpcMgmtEpEltInqNextW", "Returns one element from an endpoint map."),
        func.create("RpcMgmtEpEltInqBegin", "Creates an inquiry context for viewing the elements in an endpoint map."),
        func.create("I_RpcGetCurrentCallHandle", "Returns the current RPC call handle."),
        func.create("NdrClientCall2", "Packs data and makes a remote procedure call."),
        func.create("RpcMgmtEpEltInqDone", "Deletes the inquiry context."),
        func.create("RpcBindingFromStringBindingW", "Returns a binding handle from a string representation of a binding handle."),
        func.create("RpcStringBindingComposeW", "Creates a string binding handle."),
        func.create("MesEncodeIncrementalHandleCreate", "Creates an encoding handle for the incremental style of serialization."),
        func.create("RpcBindingSetAuthInfoExW", "Sets a server's authentication and authorization information."),
        func.create("RpcBindingInqAuthClientW", "Obtains the principal name or security-quality-of-service of the client that made the remote procedure call."),
        func.create("RpcBindingSetOption", "Sets a binding handle option."),
        func.create("RpcImpersonateClient", "Allows the server to impersonate the client that made the call."),
        func.create("RpcBindingFree", "Frees binding-handle resources."),
        func.create("RpcStringFreeW", "Frees a character string allocated by the RPC run-time library."),
        func.create("RpcRevertToSelf", "Terminates an impersonation."),
        func.create("MesDecodeIncrementalHandleCreate", "Creates a decoding handle for the incremental style of serialization."),
        func.create("MesHandleFree", "Frees the memory allocated for a handle."),
        func.create("MesIncrementalHandleReset", "Resets an incremental serialization handle."),
        func.create("NdrMesTypeDecode2", "Decodes a data type into a buffer."),
        func.create("NdrMesTypeAlignSize2", "Calculates the alignment size of a data type."),
        func.create("NdrMesTypeFree2", "Frees a decoded data type."),
        func.create("NdrMesTypeEncode2", "Encodes a data type into a buffer."),
        func.create("RpcServerUnregisterIfEx", "Unregisters an interface from the RPC run-time library."),
        func.create("I_RpcBindingInqSecurityContext", "Queries the security context of a binding."),
        func.create("RpcServerInqBindings", "Returns the binding handles over which remote procedure calls can be received."),
        func.create("RpcServerListen", "Tells the RPC run-time library to listen for remote procedure calls."),
        func.create("RpcMgmtWaitServerListen", "Waits for the server to start listening for remote procedure calls."),
        func.create("RpcEpRegisterW", "Adds to the endpoint-map database."),
        func.create("RpcMgmtStopServerListening", "Stops a server from listening for remote procedure calls."),
        func.create("RpcBindingToStringBindingW", "Returns a string representation of a binding handle."),
        func.create("RpcServerRegisterIf2", "Registers an interface with the RPC run-time library."),
        func.create("RpcServerRegisterAuthInfoW", "Registers authentication information for a server."),
        func.create("RpcBindingVectorFree", "Frees the binding handles in a vector and the vector itself."),
        func.create("UuidToStringW", "Converts a UUID to a string."),
        func.create("RpcServerUseProtseqEpW", "Tells the RPC run-time library to use the specified protocol sequence combined with the specified endpoint for receiving remote procedure calls."),
        func.create("RpcEpUnregister", "Removes server address information from the endpoint-map database."),
        func.create("NdrServerCall2", "Dispatches a remote procedure call to the server-side stub."),
        func.create("RpcEpResolveBinding", "Resolves an endpoint-map element and returns a binding handle."),
        func.create("UuidCreate", "Creates a new UUID."),
    ]
    .to_vec();
    dlls.insert("rpcrt4.dll".to_string(), funcs);

    // shell32.dll - Windows Shell API
    let funcs: Vec<Func> = [
        func.create("ShellExecuteA", "Executes a specified file."),
        func.create("ShellExecuteW", "Executes a specified file (Unicode)."),
        func.create("SHGetFolderPathW", "Gets the path of a special folder."),
        func.create(
            "SHGetSpecialFolderPathA",
            "Retrieves the path of a special folder.",
        ),
        func.create("CommandLineToArgvW", "Parses a Unicode command line string and returns an array of pointers to the command line arguments, along with a count of such arguments, in a way that is similar to the standard C run-time."),
    ]
    .to_vec();
    dlls.insert("shell32.dll".to_string(), funcs);

    // shlwapi.dll - Shell Light-weight Utility API
    let funcs: Vec<Func> = [
        func.create("pathappend", "Appends one path to another."),
        func.create("strstrA", "Searches for a substring in a string."),
        func.create("PathFileExistsA", "Checks if a file exists."),
        func.create("PathFileExistsW", "Checks if a file exists (Unicode)."),
        func.create("PathFindExtensionA", "Finds the extension of a file."),
        func.create("PathFindFileNameA", "Finds the file name in a path."),
        func.create("PathIsDirectoryW", "Verifies that a path is a valid directory. This is the Unicode version."),
        func.create("PathCanonicalizeW", "Simplifies a path by removing navigation elements such as '.' and '..'. This is the Unicode version."),
        func.create("PathCombineW", "Combines two strings that represent properly formed paths into one path; also concatenates any arguments that may be present. This is the Unicode version."),
        func.create("PathFindFileNameW", "Searches a path for a file name. This is the Unicode version."),
        func.create("PathIsRelativeW", "Searches a path and determines if it is relative. This is the Unicode version."),
    ]
    .to_vec();
    dlls.insert("shlwapi.dll".to_string(), funcs);

    // urlmon.dll - URL Moniker library for URL handling
    let funcs: Vec<Func> = [
        func.create(
            "URLDownloadToFileA",
            "Downloads the specified resource to a local file. This is the ANSI version.",
        ),
        func.create(
            "URLDownloadToFileW",
            "Downloads the specified resource to a local file. This is the Unicode version.",
        ),
    ]
    .to_vec();
    dlls.insert("urlmon.dll".to_string(), funcs);

    // user32.dll - User Interface API (windows, messages)
    let funcs: Vec<Func> = [
        func.create("setwindowlonga", "Sets the window procedure for a window."),
        func.create(
            "setwindowlongw",
            "Sets the window procedure for a window. This is the Unicode version.",
        ),
        func.create("IsCharAlphaNumericW", "Determines whether a character is either an alphabetical or a numeric character. This is the Unicode version."),
        func.create("GetKeyboardLayout", "Retrieves the active input locale identifier (formerly called the keyboard layout)."),
        func.create("DispatchMessageW", "Dispatches a message to a window procedure. This is the Unicode version."),
        func.create("DefWindowProcW", "Calls the default window procedure to provide default processing for any window messages that an application does not process. This is the Unicode version."),
        func.create("SetClipboardViewer", "Adds the specified window to the chain of clipboard viewers."),
        func.create("SendMessageW", "Sends the specified message to a window or windows. This is the Unicode version."),
        func.create("GetClipboardSequenceNumber", "Retrieves the clipboard sequence number for the current window station."),
        func.create("OpenClipboard", "Opens the clipboard for examination and prevents other applications from modifying the clipboard content."),
        func.create("CreateWindowExW", "Creates an overlapped, pop-up, or child window with an extended window style. This is the Unicode version."),
        func.create("ChangeClipboardChain", "Removes a window from the chain of clipboard viewers."),
        func.create("GetClipboardData", "Retrieves data from the clipboard in a specified format."),
        func.create("RegisterClassExW", "Registers a window class for subsequent use in calls to the CreateWindow or CreateWindowEx function. This is the Unicode version."),
        func.create("TranslateMessage", "Translates virtual-key messages into character messages."),
        func.create("EnumClipboardFormats", "Enumerates the data formats currently available on the clipboard."),
        func.create("PostMessageW", "Places (posts) a message in the message queue associated with the thread that created the specified window and returns without waiting for the thread to process the message. This is the Unicode version."),
        func.create("UnregisterClassW", "Unregisters a window class, freeing the memory required for the class. This is the Unicode version."),
        func.create("GetMessageW", "Retrieves a message from the calling thread's message queue. This is the Unicode version."),
        func.create("CloseClipboard", "Closes the clipboard."),
        func.create("DestroyWindow", "Destroys the specified window."),
    ]
    .to_vec();
    dlls.insert("user32.dll".to_string(), funcs);

    // userenv.dll - User Environment API (profiles)
    let funcs: Vec<Func> = [
        func.create(
            "GetUserProfileDirectoryA",
            "Gets the path to the user's profile directory.",
        ),
        func.create(
            "GetUserProfileDirectoryW",
            "Gets the path to the user's profile directory (Unicode).",
        ),
        func.create(
            "CreateEnvironmentBlock",
            "Retrieves the environment variables for the specified user.",
        ),
        func.create(
            "DestroyEnvironmentBlock",
            "Frees environment variables created by the CreateEnvironmentBlock function.",
        ),
    ]
    .to_vec();
    dlls.insert("userenv.dll".to_string(), funcs);

    // vbe7.dll - Visual Basic for Applications 7 runtime
    let funcs: Vec<Func> = [func.create(
        "__vbaexcepthandler",
        "Internal exception handler used by Visual Basic for Applications runtime.",
    )]
    .to_vec();
    dlls.insert("vbe7.dll".to_string(), funcs);

    // winhttp.dll - Windows HTTP Services
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
        func.create("httpopenrequesta", "Creates an HTTP request handle. This is the ANSI version."),
        func.create("httpqueryinfoa", "Retrieves header information associated with an HTTP request. This is the ANSI version."),
    ]
    .to_vec();
    dlls.insert("winhttp.dll".to_string(), funcs);

    // wininet.dll - Windows Internet API
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
        func.create("getprofileinta", "Retrieves an integer from a key in the specified section of the Win.ini file."),
        func.create("inet_addr", "Converts a string containing an IPv4 dotted-decimal address into a proper address for the IN_ADDR structure."),
    ]
    .to_vec();
    dlls.insert("wininet.dll".to_string(), funcs);

    // ws2_32.dll - Winsock 2.0 API
    let funcs: Vec<Func> = [
        func.create(
            "wsaasyncgethostbyname",
            "Asynchronously retrieves host information that corresponds to a hostname.",
        ),
        func.create(
            "wsaconnect",
            "Establishes a connection to a specified socket.",
        ),
    ]
    .to_vec();
    dlls.insert("ws2_32.dll".to_string(), funcs);

    // wsock32.dll - Windows socket functions (legacy)
    let funcs: Vec<Func> = [
        func.create(
            "wsaconnect",
            "Establishes a connection to a specified socket.",
        ),
        func.create("wsend", "Sends data over a socket."),
        func.create("wrecv", "Receives data from a socket."),
    ]
    .to_vec();
    dlls.insert("wsock32.dll".to_string(), funcs);

    // ELF

    // libc – core system calls & memory ops
    let funcs: Vec<Func> = [
        func.create("dlopen", "Open a shared object and return a handle."),
        func.create(
            "dlsym",
            "Look up a symbol in the shared object referenced by a handle.",
        ),
        func.create("dlclose", "Close a shared object opened with dlopen."),
        func.create(
            "_dl_iterate_phdr",
            "Iterate over program headers of loaded modules (used for introspection).",
        ),
        func.create(
            "mprotect",
            "Change protection on memory pages – often used in exploits.",
        ),
        func.create(
            "execve",
            "Execute a program, replacing the current process image.",
        ),
        func.create(
            "ptrace",
            "Trace and manipulate other processes – key forensic indicator.",
        ),
        func.create("getuid", "Get the real user ID of the calling process."),
        func.create("getgid", "Get the real group ID of the calling process."),
    ]
    .to_vec();
    dlls.insert("libc.so.6".to_string(), funcs);

    // libdl – dynamic linking helpers
    let funcs: Vec<Func> = [
        func.create("__libc_dlerror", "Return error message from last dl* call."),
        func.create(
            "__libc_dlopen_mode",
            "Internal helper for dlopen with mode flags.",
        ),
        func.create("dlerror", "Return error message from last dl* call."),
    ]
    .to_vec();
    dlls.insert("libdl.so.2".to_string(), funcs);

    // libpthread – threading primitives
    let funcs: Vec<Func> = [
        func.create("pthread_create", "Create a new thread."),
        func.create("pthread_join", "Wait for a thread to terminate."),
        func.create("pthread_mutex_lock", "Lock a mutex."),
        func.create("pthread_mutex_unlock", "Unlock a mutex."),
        func.create("pthread_cond_wait", "Wait on a condition variable."),
        func.create("pthread_attr_init", "Initialize thread attributes object."),
    ]
    .to_vec();
    dlls.insert("libpthread.so.0".to_string(), funcs);

    // libcrypto – cryptographic primitives
    let funcs: Vec<Func> = [
        func.create(
            "EVP_encrypt_init_ex",
            "Initialize encryption context (OpenSSL).",
        ),
        func.create("EVP_decrypt_update", "Decrypt data chunk (OpenSSL)."),
        func.create("RAND_bytes", "Generate random bytes (OpenSSL)."),
        func.create("sha256", "Compute SHA256 hash of input data."),
        func.create("aes_encrypt", "Encrypt data using AES algorithm."),
    ]
    .to_vec();
    dlls.insert("libcrypto.so.1.1".to_string(), funcs);

    // libm – math functions that can be abused
    let funcs: Vec<Func> = [
        func.create("__ieee754_sqrt", "Square root implementation."),
        func.create("__pow10f", "Compute 10^x for float."),
        func.create("cos", "Compute cosine of argument."),
        func.create("sin", "Compute sine of argument."),
    ]
    .to_vec();
    dlls.insert("libm.so.6".to_string(), funcs);

    // librt.so.1 - Real-time library functions
    let funcs: Vec<Func> = [
        func.create("clock_gettime", "Get current time of specified clock."),
        func.create(
            "pthread_timedjoin_np",
            "Wait for a thread to terminate with timeout.",
        ),
    ]
    .to_vec();
    dlls.insert("librt.so.1".to_string(), funcs);

    // libssl.so.1.1 - SSL/TLS functions
    let funcs: Vec<Func> = [
        func.create("ssl_connect", "Initiate SSL/TLS connection."),
        func.create("ssl_write", "Write data to an SSL/TLS connection."),
        func.create("ssl_read", "Read data from an SSL/TLS connection."),
    ]
    .to_vec();
    dlls.insert("libssl.so.1.1".to_string(), funcs);

    // Mach-O

    // libSystem.B.dylib - Core system library functions
    let funcs: Vec<Func> = [
        func.create("dyld", "Dynamic linker function used to load libraries."),
        func.create("malloc", "Memory allocation function used by applications."),
        func.create("free", "Memory deallocation function used by applications."),
        func.create("pthread_create", "Create a new thread in the system."),
        func.create("pthread_join", "Wait for a thread to terminate."),
        func.create("clock_gettime", "Get current time of specified clock."),
    ]
    .to_vec();
    dlls.insert("libSystem.B.dylib".to_string(), funcs);

    // libcurl.dylib - Network operations with forensic significance
    let funcs: Vec<Func> = [
        func.create("curl_easy_init", "Initialize an HTTP connection handle."),
        func.create("curl_easy_perform", "Perform a network request operation."),
        func.create(
            "curl_easy_getinfo",
            "Retrieve information from completed transfers.",
        ),
        func.create("curl_easy_cleanup", "Clean up curl handle resources."),
        func.create("curl_version", "Get version of libcurl library."),
        func.create("curl_easy_setopt", "Set options for a curl easy handle."),
    ]
    .to_vec();
    dlls.insert("libcurl.dylib".to_string(), funcs);

    // SecurityFoundation framework - Security functions
    let funcs: Vec<Func> = [
        func.create(
            "SecTrustEvaluate",
            "Evaluate certificate trust relationships.",
        ),
        func.create("SecKeyGenerate", "Generate cryptographic keys."),
        func.create(
            "SecRandomCopyBytes",
            "Generate random bytes for security operations.",
        ),
        func.create("secitemcopymatching", "Copy matching items from keychain."),
    ]
    .to_vec();
    dlls.insert("SecurityFoundation.framework".to_string(), funcs);

    // CoreFoundation framework - Core system functions
    let funcs: Vec<Func> = [
        func.create(
            "CFStringCreateWithCString",
            "Create a string from C-style string.",
        ),
        func.create("CFDictionaryGetValue", "Get value from dictionary entry."),
        func.create(
            "CFArrayGetValueAtIndex",
            "Get value at specific array index.",
        ),
        func.create("cfstringgetcstring", "Convert CFString to C-style string."),
    ]
    .to_vec();
    dlls.insert("CoreFoundation.framework".to_string(), funcs);

    // api-ms-win-core-synch-l1-2-0.dll - Core synchronization functions
    let funcs: Vec<Func> = [
        func.create(
            "waitonaddress",
            "Waits for an address to be signaled or timeout.",
        ),
        func.create(
            "wakebyaddressall",
            "Wakes all threads waiting on the specified address.",
        ),
        func.create(
            "wakebyaddresssingle",
            "Wakes a single thread waiting on the specified address.",
        ),
    ]
    .to_vec();
    dlls.insert("api-ms-win-core-synch-l1-2-0.dll".to_string(), funcs);

    // bcryptprimitives.dll - Cryptography primitives
    let funcs: Vec<Func> = [func.create(
        "processprng",
        "Processes a pseudo-random number generator for cryptographic operations.",
    )]
    .to_vec();
    dlls.insert("bcryptprimitives.dll".to_string(), funcs);

    // msvcrt.dll - Microsoft Visual C++ Runtime
    let funcs: Vec<Func> = [
        func.create("__getmainargs", "Gets the main arguments of the program."),
        func.create("__initenv", "Initializes environment variables."),
        func.create(
            "__iob_func",
            "Returns a pointer to the standard input/output streams.",
        ),
        func.create(
            "__set_app_type",
            "Sets the application type for error handling.",
        ),
        func.create("__setusermatherr", "Sets user-defined math error handler."),
        func.create(
            "_amsg_exit",
            "Displays an error message and exits the program.",
        ),
        func.create("_cexit", "Cleans up C runtime environment before exit."),
        func.create("_commode", "Sets the default mode for standard streams."),
        func.create("_errno", "Retrieves the last error number."),
        func.create("_fmode", "Gets or sets the file mode for standard streams."),
        func.create("_fpreset", "Resets floating-point environment."),
        func.create("_initterm", "Initializes termination functions."),
        func.create("_onexit", "Registers exit handlers."),
        func.create("abort", "Aborts execution and exits with an error code."),
        func.create("calloc", "Allocates memory for arrays of objects."),
        func.create("exit", "Terminates the calling process."),
        func.create("fprintf", "Prints formatted output to a stream."),
        func.create("free", "Frees memory allocated by malloc or calloc."),
        func.create("fwrite", "Writes data to a stream."),
        func.create("logf", "Computes the natural logarithm of the argument."),
        func.create("malloc", "Allocates memory for objects."),
        func.create("memcmp", "Compares two memory regions."),
        func.create("memcpy", "Copies memory from source to destination."),
        func.create("memmove", "Moves memory with overlap handling."),
        func.create("memset", "Sets a memory region to a specific value."),
        func.create("signal", "Sets a signal handler for the specified signal."),
        func.create("strlen", "Returns the length of a string."),
        func.create("strncmp", "Compares two strings up to n characters."),
        func.create(
            "vfprintf",
            "Prints formatted output to a stream using variable arguments.",
        ),
        func.create(
            "isspace",
            "Checks if a character is a whitespace character.",
        ),
        func.create("isdigit", "Checks if a character is a decimal digit."),
        func.create(
            "mbtowc",
            "Converts a multibyte character to a wide character.",
        ),
        func.create(
            "_lseeki64",
            "Moves the file pointer to a specified location (64-bit).",
        ),
        func.create("_write", "Writes data to a file."),
        func.create(
            "isleadbyte",
            "Determines if a character is a lead byte of a multibyte character.",
        ),
        func.create("isxdigit", "Checks if a character is a hexadecimal digit."),
        func.create(
            "localeconv",
            "Retrieves detailed information on locale settings.",
        ),
        func.create(
            "_snprintf",
            "Writes formatted data to a string of a specified size.",
        ),
        func.create("_itoa", "Converts an integer to a string."),
        func.create(
            "wctomb",
            "Converts a wide character to a multibyte character.",
        ),
        func.create("ferror", "Checks for an error in a stream."),
        func.create(
            "iswctype",
            "Classifies wide characters by their character type.",
        ),
        func.create(
            "wcstombs",
            "Converts a sequence of wide characters to a sequence of multibyte characters.",
        ),
        func.create(
            "_isatty",
            "Determines if a file descriptor is associated with a character device.",
        ),
        func.create("ungetc", "Pushes a character back to the stream."),
        func.create("?terminate @@YAXXZ", "C++ terminate handler."),
        func.create("__badioinfo", "Internal CRT function."),
        func.create("__pioinfo", "Internal CRT function."),
        func.create("_read", "Reads data from a file."),
        func.create("log", "Computes the natural logarithm."),
        func.create(
            "__mb_cur_max",
            "Gets the maximum number of bytes in a multibyte character for the current locale.",
        ),
        func.create(
            "vwprintf",
            "Writes formatted output using a pointer to a list of arguments.",
        ),
        func.create("_wcsdup", "Duplicates a wide-character string."),
        func.create(
            "_vsnprintf",
            "Writes formatted data of a specified size to a string.",
        ),
        func.create(
            "strrchr",
            "Locates the last occurrence of a character in a string.",
        ),
        func.create(
            "_wcsicmp",
            "Performs a case-insensitive comparison of wide-character strings.",
        ),
        func.create(
            "vfwprintf",
            "Writes formatted output to a stream using a pointer to a list of arguments.",
        ),
        func.create(
            "_vscwprintf",
            "Returns the number of characters required to write formatted data to a string.",
        ),
        func.create("fflush", "Flushes a stream."),
        func.create("_wfopen", "Opens a file with a wide-character file name."),
        func.create(
            "wprintf",
            "Writes formatted output to the standard output stream.",
        ),
        func.create(
            "_fileno",
            "Gets the file descriptor associated with a stream.",
        ),
        func.create("_iob", "Pointer to an array of stream control structures."),
        func.create("_setmode", "Sets the file translation mode."),
        func.create("fclose", "Closes a stream."),
        func.create(
            "_stricmp",
            "Performs a case-insensitive comparison of strings.",
        ),
        func.create(
            "wcsrchr",
            "Locates the last occurrence of a wide character in a wide-character string.",
        ),
        func.create(
            "wcschr",
            "Locates the first occurrence of a wide character in a wide-character string.",
        ),
        func.create("strtoul", "Converts a string to an unsigned long integer."),
        func.create(
            "_wcsnicmp",
            "Performs a case-insensitive comparison of a specified number of wide characters.",
        ),
        func.create("wcsstr", "Locates a wide-character substring."),
        func.create(
            "_vscprintf",
            "Returns the number of characters required to write formatted data to a string.",
        ),
        func.create(
            "_msize",
            "Returns the size of a memory block allocated from the heap.",
        ),
        func.create(
            "strcspn",
            "Finds the first character in a string that is also in a set of characters.",
        ),
        func.create("realloc", "Reallocates a memory block."),
        func.create("fgetws", "Gets a wide-character string from a stream."),
        func.create(
            "wcstoul",
            "Converts a wide-character string to an unsigned long integer.",
        ),
        func.create(
            "wcstol",
            "Converts a wide-character string to a long integer.",
        ),
        func.create("towupper", "Converts a wide character to uppercase."),
        func.create("_wpgmptr", "Pointer to the wide-character program name."),
        func.create("strstr", "Locates a substring."),
        func.create(
            "strchr",
            "Locates the first occurrence of a character in a string.",
        ),
        func.create(
            "_wcstoui64",
            "Converts a wide-character string to an unsigned 64-bit integer.",
        ),
        func.create(
            "wcsncmp",
            "Compares a specified number of wide characters in two strings.",
        ),
        func.create(
            "getchar",
            "Gets a character from the standard input stream.",
        ),
        func.create("__C_specific_handler", "The C-specific exception handler."),
        func.create(
            "__wgetmainargs",
            "Internal CRT function to get main arguments.",
        ),
        func.create(
            "_XcptFilter",
            "The exception filter expression used by the C run-time library.",
        ),
        func.create("_exit", "Terminates the calling process."),
    ]
    .to_vec();
    dlls.insert("msvcrt.dll".to_string(), funcs);

    // WebKit framework - Web browser engine functions
    let funcs: Vec<Func> = [
        func.create("WKWebView", "Create and manage web view components."),
        func.create("WebFrame", "Manage frame manipulation operations."),
        func.create(
            "WebKitEvaluateJavaScript",
            "Execute JavaScript in web context.",
        ),
        func.create("wkwebviewloadrequest", "Load request with specified URL."),
    ]
    .to_vec();
    dlls.insert("WebKit.framework".to_string(), funcs);

    // Cabinet.dll - Cabinet file API
    let funcs: Vec<Func> = [
        func.create(
            "ORDINAL 11",
            "FDICreate: Creates a File Decompression Interface (FDI) context.",
        ),
        func.create(
            "ORDINAL 14",
            "FDITruncateCabinet: Truncates a cabinet file at a specified folder number.",
        ),
        func.create(
            "ORDINAL 10",
            "FDICopy: Extracts a file from a cabinet, decompressing it in the process.",
        ),
        func.create(
            "ORDINAL 13",
            "FDIDestroy: Destroys an open FDI context, freeing its memory.",
        ),
    ]
    .to_vec();
    dlls.insert("cabinet.dll".to_string(), funcs);

    // cryptdll.dll - Cryptography functions
    let funcs: Vec<Func> = [
        func.create("MD5Init", "Initializes an MD5 hash object."),
        func.create("MD5Update", "Updates an MD5 hash object."),
        func.create("MD5Final", "Finalizes an MD5 hash object."),
        func.create("CDLocateCSystem", "Undocumented function."),
        func.create("CDGenerateRandomBits", "Generates random bits."),
        func.create("CDLocateCheckSum", "Calculates a checksum."),
    ]
    .to_vec();
    dlls.insert("cryptdll.dll".to_string(), funcs);

    // dnsapi.dll - DNS API
    let funcs: Vec<Func> = [
        func.create("DnsFree", "Frees memory allocated for DNS data."),
        func.create(
            "DnsQuery_A",
            "Retrieves host A records for a given DNS name.",
        ),
    ]
    .to_vec();
    dlls.insert("dnsapi.dll".to_string(), funcs);

    // fltlib.dll - Filter Manager Library
    let funcs: Vec<Func> = [
        func.create(
            "FilterFindFirst",
            "Starts enumerating minifilter drivers in the system.",
        ),
        func.create(
            "FilterFindNext",
            "Continues a minifilter driver search started by a call to FilterFindFirst.",
        ),
    ]
    .to_vec();
    dlls.insert("fltlib.dll".to_string(), funcs);

    // ole32.dll - OLE API
    let funcs: Vec<Func> = [
        func.create("CoInitializeEx", "Initializes the COM library for use by the calling thread, sets the thread's concurrency model, and creates a new apartment for the thread if one is required."),
        func.create("CoUninitialize", "Closes the COM library on the current thread, unloads all DLLs loaded by the thread, frees any other resources that the thread maintains, and forces all RPC connections on the thread to close."),
        func.create("CoCreateInstance", "Creates and initializes a single object of the class associated with a specified CLSID."),
    ]
    .to_vec();
    dlls.insert("ole32.dll".to_string(), funcs);

    // samlib.dll - Security Account Manager library
    let funcs: Vec<Func> = [
        func.create(
            "SamEnumerateGroupsInDomain",
            "Enumerates all groups in the specified domain.",
        ),
        func.create("SamiChangePasswordUser", "Changes a user's password."),
        func.create("SamSetInformationUser", "Sets information for a user."),
        func.create(
            "SamGetGroupsForUser",
            "Retrieves the groups that a user belongs to.",
        ),
        func.create("SamConnect", "Connects to the SAM server."),
        func.create("SamGetMembersInGroup", "Retrieves the members of a group."),
        func.create("SamRidToSid", "Converts a RID to a SID."),
        func.create("SamGetMembersInAlias", "Retrieves the members of an alias."),
        func.create(
            "SamEnumerateAliasesInDomain",
            "Enumerates all aliases in the specified domain.",
        ),
        func.create(
            "SamGetAliasMembership",
            "Retrieves the aliases that a user belongs to.",
        ),
        func.create("SamOpenGroup", "Opens a group."),
        func.create(
            "SamQueryInformationUser",
            "Queries information about a user.",
        ),
        func.create("SamCloseHandle", "Closes a SAM handle."),
        func.create(
            "SamEnumerateDomainsInSamServer",
            "Enumerates all domains in the SAM server.",
        ),
        func.create("SamFreeMemory", "Frees memory allocated by a SAM function."),
        func.create(
            "SamEnumerateUsersInDomain",
            "Enumerates all users in the specified domain.",
        ),
        func.create("SamOpenUser", "Opens a user."),
        func.create(
            "SamLookupDomainInSamServer",
            "Looks up a domain in the SAM server.",
        ),
        func.create("SamLookupNamesInDomain", "Looks up names in a domain."),
        func.create("SamLookupIdsInDomain", "Looks up RIDs in a domain."),
        func.create("SamOpenDomain", "Opens a domain."),
        func.create("SamOpenAlias", "Opens an alias."),
    ]
    .to_vec();
    dlls.insert("samlib.dll".to_string(), funcs);

    // secur32.dll - Security Support Provider API
    let funcs: Vec<Func> = [
        func.create("QueryContextAttributesW", "Enables a transport application to query certain attributes of a security context for a security package."),
        func.create("FreeContextBuffer", "Frees a memory buffer allocated by a security package."),
        func.create("LsaConnectUntrusted", "Establishes an untrusted connection to the LSA server."),
        func.create("LsaLookupAuthenticationPackage", "Obtains the unique identifier of an authentication package."),
        func.create("LsaDeregisterLogonProcess", "Deregisters a logon application from the LSA server."),
        func.create("DeleteSecurityContext", "Deletes the local data structures associated with a security context."),
        func.create("LsaCallAuthenticationPackage", "Allows a logon application to communicate with an authentication package."),
        func.create("FreeCredentialsHandle", "Frees the memory used by a credentials handle."),
        func.create("EnumerateSecurityPackagesW", "Returns an array of SecPkgInfoW structures that provide information about the security packages available to the client."),
        func.create("AcquireCredentialsHandleW", "Acquires a handle to preexisting credentials of a security principal."),
        func.create("InitializeSecurityContextW", "Initiates the client side of a security context from a credential handle."),
        func.create("LsaFreeReturnBuffer", "Frees the memory used by a buffer previously allocated by the LSA."),
    ]
    .to_vec();
    dlls.insert("secur32.dll".to_string(), funcs);

    // version.dll - Version information API
    let funcs: Vec<Func> = [
        func.create("VerQueryValueW", "Retrieves specified version information from the specified version-information resource."),
        func.create("GetFileVersionInfoSizeW", "Determines whether the operating system can retrieve version information for a specified file."),
        func.create("GetFileVersionInfoW", "Retrieves version information for the specified file."),
    ]
    .to_vec();
    dlls.insert("version.dll".to_string(), funcs);

    // hid.dll - Human Interface Device API
    let funcs: Vec<Func> = [
        func.create("HidD_GetFeature", "Returns a feature report from a specified top-level collection."),
        func.create("HidD_GetPreparsedData", "Returns a top-level collection's preparsed data."),
        func.create("HidD_GetHidGuid", "Returns the device interface GUID for HIDClass devices."),
        func.create("HidD_GetAttributes", "Returns the attributes of a specified top-level collection."),
        func.create("HidD_FreePreparsedData", "Releases the resources that the HID class driver allocated to hold a top-level collection's preparsed data."),
        func.create("HidP_GetCaps", "Returns a top-level collection's HIDP_CAPS structure."),
        func.create("HidD_SetFeature", "Sends a feature report to a top-level collection."),
    ]
    .to_vec();
    dlls.insert("hid.dll".to_string(), funcs);

    // setupapi.dll - Device installation API
    let funcs: Vec<Func> = [
        func.create("SetupDiGetDeviceInterfaceDetailW", "Returns details about a device interface."),
        func.create("SetupDiEnumDeviceInterfaces", "Enumerates the device interfaces that are contained in a device information set."),
        func.create("SetupDiGetClassDevsW", "Returns a handle to a device information set that contains requested device information elements for a local computer."),
        func.create("SetupDiDestroyDeviceInfoList", "Destroys a device information set and frees all associated memory."),
    ]
    .to_vec();
    dlls.insert("setupapi.dll".to_string(), funcs);

    // winscard.dll - Smart Card API
    let funcs: Vec<Func> = [
        func.create("SCardControl", "Sends a command directly to the smart card reader."),
        func.create("SCardTransmit", "Sends a service request to the smart card."),
        func.create("SCardDisconnect", "Terminates a connection made through the SCardConnect function."),
        func.create("SCardGetAttrib", "Gets a card attribute from the ICC."),
        func.create("SCardEstablishContext", "Establishes the resource manager context (the scope) within which database operations are performed."),
        func.create("SCardFreeMemory", "Releases memory that has been returned from the resource manager using the SCARD_AUTOALLOCATE length designator."),
        func.create("SCardListReadersW", "Provides the list of readers within a set of named reader groups, eliminating duplicates."),
        func.create("SCardReleaseContext", "Closes an established resource manager context, freeing any resources allocated under that context."),
        func.create("SCardGetCardTypeProviderNameW", "Returns the name of the provider for a given card type."),
        func.create("SCardListCardsW", "Searches the smart card database and provides a list of cards that have been introduced to the system by the user."),
        func.create("SCardConnectW", "Establishes a connection (a communication channel) between the calling application and a smart card contained by a specific reader."),
    ]
    .to_vec();
    dlls.insert("winscard.dll".to_string(), funcs);

    // winsta.dll - Window Station and Desktop API
    let funcs: Vec<Func> = [
        func.create(
            "WinStationCloseServer",
            "Closes a handle to a Remote Desktop Services server.",
        ),
        func.create(
            "WinStationOpenServerW",
            "Opens a handle to a Remote Desktop Services server.",
        ),
        func.create(
            "WinStationFreeMemory",
            "Frees memory allocated by a WinStation function.",
        ),
        func.create(
            "WinStationConnectW",
            "Connects a session to an existing session on the local computer.",
        ),
        func.create(
            "WinStationQueryInformationW",
            "Retrieves information about a Remote Desktop Services session.",
        ),
        func.create(
            "WinStationEnumerateW",
            "Enumerates all Remote Desktop Services sessions on a specified server.",
        ),
    ]
    .to_vec();
    dlls.insert("winsta.dll".to_string(), funcs);

    // wldap32.dll - LDAP API
    let funcs: Vec<Func> = [
        func.create("ORDINAL 122", "LdapMapErrorToWin32: Converts an LDAP error code to a Windows error code."),
        func.create("ORDINAL 14", "cldap_open: Obsolete function to initialize a session with an LDAP server over UDP."),
        func.create("ORDINAL 88", "ldap_ufn2dn: Converts a user-friendly name to a Distinguished Name (DN)."),
        func.create("ORDINAL 157", "ldap_create_sort_control: Creates a control for sorting search results."),
        func.create("ORDINAL 133", "ldap_stop_tls_s: Stops a TLS-encrypted session."),
        func.create("ORDINAL 27", "ldap_count_references: Counts the number of continuation references returned by a search."),
        func.create("ORDINAL 147", "ber_scanf: Decodes a BER element using a format string."),
        func.create("ORDINAL 167", "ldap_set_dbg_flags: Sets debug flags for the LDAP library."),
        func.create("ORDINAL 26", "ldap_count_entries: Counts the number of entries in a search result chain."),
        func.create("ORDINAL 127", "ldap_get_option: Retrieves the current value of session-wide parameters."),
        func.create("ORDINAL 224", "ldap_err2string: Converts an LDAP error code to a descriptive string."),
        func.create("ORDINAL 113", "ldap_first_attribute: Retrieves the first attribute in a given entry."),
        func.create("ORDINAL 309", "ldap_conn_per_thread_init: Initializes per-thread connection management."),
        func.create("ORDINAL 54", "ldap_search_s: Synchronously performs an LDAP search operation."),
        func.create("ORDINAL 142", "ber_alloc_t: Allocates a new BerElement structure."),
        func.create("ORDINAL 77", "ldap_result: Waits for and returns the result of an asynchronous operation."),
        func.create("ORDINAL 13", "cldap_close: Obsolete function to close a UDP-based LDAP session."),
        func.create("ORDINAL 208", "ldap_simple_bind_s: Synchronously authenticates to a server using a username and password."),
        func.create("ORDINAL 145", "ber_printf: Encodes data into a BerElement using a format string."),
        func.create("ORDINAL 36", "ldap_get_values_len: Retrieves a set of binary values for a given attribute."),
        func.create("ORDINAL 79", "ldap_set_option: Sets session-wide parameters."),
        func.create("ORDINAL 41", "ldap_memfree: Frees memory allocated by the LDAP library."),
        func.create("ORDINAL 73", "ldap_parse_result: Parses the results returned from an LDAP operation."),
        func.create("ORDINAL 310", "ldap_conn_per_thread_cleanup: Cleans up per-thread connection management."),
        func.create("ORDINAL 203", "ldap_search_ext_s: Synchronously performs an extended LDAP search with controls."),
        func.create("ORDINAL 69", "ldap_next_entry: Retrieves the next entry in a chain of search results."),
        func.create("ORDINAL 139", "LdapGetLastError: Retrieves the last error code set for the calling thread."),
        func.create("ORDINAL 97", "ldap_add_s: Synchronously performs an LDAP add operation."),
        func.create("ORDINAL 223", "ldap_controls_free: Frees an array of LDAPControl structures."),
        func.create("ORDINAL 304", "ldap_create_vlv_control: Creates a control for virtual list view (VLV) searches."),
        func.create("ORDINAL 12", "ldap_abandon: Abandons or cancels an asynchronous LDAP operation."),
        func.create("ORDINAL 96", "ldap_add: Asynchronously performs an LDAP add operation."),
        func.create("ORDINAL 301", "ldap_search_abandon_page: Abandons a paged search operation."),
        func.create("ORDINAL 140", "LdapUTF8ToUnicode: Converts a UTF-8 string to a Unicode string."),
    ].to_vec();
    dlls.insert("wldap32.dll".to_string(), funcs);

    // msasn1.dll - ASN.1 parsing API
    let funcs: Vec<Func> = [
        func.create("ASN1_CreateModule", "Creates an ASN.1 module."),
        func.create(
            "ASN1BERDotVal2Eoid",
            "Converts a dotted value to an object identifier.",
        ),
        func.create("ASN1_CloseEncoder", "Closes an ASN.1 encoder."),
        func.create("ASN1_CreateDecoder", "Creates an ASN.1 decoder."),
        func.create("ASN1_FreeEncoded", "Frees an encoded ASN.1 structure."),
        func.create("ASN1_CloseModule", "Closes an ASN.1 module."),
        func.create("ASN1_CreateEncoder", "Creates an ASN.1 encoder."),
        func.create("ASN1_CloseDecoder", "Closes an ASN.1 decoder."),
    ]
    .to_vec();
    dlls.insert("msasn1.dll".to_string(), funcs);

    return dlls;
}
