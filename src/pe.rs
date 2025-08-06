use crate::data_defs::{BinSection, BinSections, Binary, BinaryFormat, BinaryInfo, PeInfo, ExpHashes, Exports, Function, ImpHashes, Import, Imports, Architecture, PeTimestamps, PeLinker, DLLS};
use crate::ordinals;
use std::path::{Path, PathBuf};
use std::io::{self, Write, Read, Seek, SeekFrom};
use std::fs::File;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use fuzzyhash::FuzzyHash;
use entropy::shannon_entropy;
use goblin::pe;
use exe;

fn get_hashmap_value(
                    string_map: &HashMap<String, String>, 
                    value_name: &str
                    ) -> io::Result<String> 
{
    let _v = match string_map.get(value_name) {
        Some(v) => return Ok(v.to_string()),
        None => return Ok("".to_string())
    };
}

fn get_date_string(timestamp: i64) -> io::Result<String> {
    let dt = match DateTime::from_timestamp(timestamp, 0) {
            Some(s) => s.format("%Y-%m-%dT%H:%M:%S").to_string(),
            None => "".to_string()
        };
    Ok(dt)
}

fn get_ssdeep_hash(mut buffer: &Vec<u8>) -> io::Result<String> {
    let ssdeep = FuzzyHash::new(buffer);
    Ok(ssdeep.to_string())
}

fn get_arch(machine: u16) -> Architecture {
    match machine {
        pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
        pe::header::COFF_MACHINE_X86 => Architecture::X86,
        pe::header::COFF_MACHINE_ARM => Architecture::Arm,
        pe::header::COFF_MACHINE_ARMNT => Architecture::AArch64,
        pe::header::COFF_MACHINE_POWERPC => Architecture::PowerPC,
        pe::header::COFF_MACHINE_IA64 => Architecture::Itanium,
        _ => Architecture::Unknown,
    }
}

fn get_pe_file_info(path: &Path, binary_info: &mut BinaryInfo) -> io::Result<()> {
    let Ok(pefile) = exe::VecPE::from_disk_file(path) else { return Ok(()) };
    let Ok(vs_version_check) = exe::VSVersionInfo::parse(&pefile) else { return Ok(()) };
    let vs_version = vs_version_check;
    if let Some(string_file_info) = vs_version.string_file_info {
        let Ok(string_map) = string_file_info.children[0].string_map() else { return Ok(()) };
        binary_info.pe_info.product_version = get_hashmap_value(&string_map, "ProductVersion")?;
        binary_info.pe_info.original_filename = get_hashmap_value(&string_map, "OriginalFilename")?;
        binary_info.pe_info.file_description = get_hashmap_value(&string_map, "FileDescription")?;
        binary_info.pe_info.file_version = get_hashmap_value(&string_map, "FileVersion")?;
        binary_info.pe_info.product_name = get_hashmap_value(&string_map, "ProductName")?;
        binary_info.pe_info.company_name = get_hashmap_value(&string_map, "CompanyName")?;
        binary_info.pe_info.internal_name = get_hashmap_value(&string_map, "InternalName")?;
        binary_info.pe_info.legal_copyright = get_hashmap_value(&string_map, "LegalCopyright")?;
    }
    Ok(())
}

fn read_section(path: &Path, start: u32, size: u32) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start as u64))?;
    let mut buf = vec![0; size as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn get_sections(pex: &pe::PE, path: &Path) -> io::Result<BinSections> {
    let mut bss = BinSections::default();
    for s in pex.sections.iter() {
        bss.total_sections += 1;
        bss.total_raw_bytes += s.size_of_raw_data;
        bss.total_virt_bytes += s.virtual_size;
        let mut bs: BinSection = BinSection::default();
        bs.name = s.name().unwrap_or("").to_string();
        bs.virt_address = format!("0x{:02x}", s.virtual_address);
        bs.raw_size = s.size_of_raw_data;
        bs.virt_size = s.virtual_size;
        let data = read_section(path, s.pointer_to_raw_data, s.size_of_raw_data)?;
        bs.entropy = shannon_entropy(&data);
        bs.md5 = format!("{:x}", md5::compute(&data)).to_lowercase();
        bs.ssdeep = get_ssdeep_hash(&data)?;
        bss.sections.push(bs);
    }
    Ok(bss)
}

fn is_dotnet(imps: &Imports) -> io::Result<bool> {
    if imps.imports.len() == 1 {
        if imps.imports[0].count ==1 
            && imps.imports[0].lib == "mscoree.dll" 
            && (
                imps.imports[0].names[0].name == "_CorExeMain" 
                || imps.imports[0].names[0].name == "_CorDllMain"
            ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_function_interesting(dll: &str, func: &str) -> (Option<bool>, String) {
    if DLLS.contains_key(dll) {
        let funcs = match DLLS.get(dll) {
            Some(it) => it,
            None => return (None, String::new()),
        };
        for f in funcs {
            if f.name.to_lowercase().eq(&func.to_lowercase()) {
                return (Some(true), f.desc.clone());
            }
        }
    }
    (None, String::new())
}

fn parse_pe_imports(imports: &Vec<goblin::pe::import::Import>) -> io::Result<(Imports, bool)> 
{
    let mut track_dlls:Vec<&str> = Vec::new();
    let mut imps: Imports = Imports::default();
    let mut func: Function = Function::default();
    for i in imports.iter() {
        if track_dlls.contains(&i.dll) { continue; }
        track_dlls.push(i.dll);
        let mut temp = Import::default();
        temp.lib = i.dll.to_string();
        for m in imports.iter() {
            if i.dll != m.dll { continue; }
            temp.count += 1;
            func.name = m.name.to_string();
            (func.more_interesting, func.info) = is_function_interesting(
                                                    &i.dll.to_lowercase(),
                                                    &func.name); 
            temp.names.push(func.clone());
        }
        imps.imports.push(temp);
    }
    let is_dot_net = is_dotnet(&imps)?;
    Ok((imps, is_dot_net))
}

fn get_hash_sorted(hash_array: &mut Vec<String>) -> io::Result<(String, String)> {
    hash_array.sort();
    let mut imphash_text_sorted = String::new();
    for i in hash_array.iter() {
        imphash_text_sorted.push_str(i);
    }
    imphash_text_sorted = imphash_text_sorted.trim_end_matches(",").to_string();
    let imphash_sorted = format!("{:x}", md5::compute(&imphash_text_sorted)).to_lowercase();

    Ok((imphash_text_sorted, imphash_sorted))
}

fn check_ordinal(dll: &str, func: &str) -> io::Result<String> {
    let mut f: String = func.to_ascii_lowercase().replace("ordinal ", "");
    if f.parse::<u32>().is_ok() {
        let o = f.parse::<u32>().unwrap();
        f = ordinals::imphash_resolve(dll, o).to_ascii_lowercase();
    }
    Ok(f)
}

fn get_imphashes(imports: &Vec<goblin::pe::import::Import>) 
                        -> io::Result<(ImpHashes, usize, usize)> {
    let mut imphash_array: Vec<String> = Vec::new();
    let mut imphash_text = String::new();
    let mut total_dlls = 0;
    let mut track_dll = String::new();
    for i in imports.iter() {
        let mut temp = String::new();
        if i.dll != track_dll { total_dlls += 1; }
        let mut dll = i.dll.to_ascii_lowercase()
            .replace(".dll", "")
            .replace(".sys", "")
            .replace(".drv", "")
            .replace(".ocx", "").to_string();
        temp.push_str(&dll);
        temp.push_str(".");
        let func = check_ordinal(i.dll, &i.name)?;
        temp.push_str(&func);
        temp.push_str(",");
        imphash_text.push_str(&temp.to_string());
        imphash_array.push(temp.to_string());
        track_dll = i.dll.to_string();
    }
    let mut imphashes = ImpHashes::default();
    imphash_text = imphash_text.trim_end_matches(",").to_string();
    imphashes.md5 = format!("{:x}", md5::compute(imphash_text.clone())).to_lowercase();
    let mut imphash_text_sorted = String::new();
    (imphash_text_sorted, imphashes.md5_sorted) = get_hash_sorted(&mut imphash_array)?;
    let imphash_bytes: Vec<u8> = imphash_text.as_bytes().to_vec();
    let imphash_bytes_ordered: Vec<u8> = imphash_text_sorted.as_bytes().to_vec();
    imphashes.ssdeep = get_ssdeep_hash(&imphash_bytes)?;
    imphashes.ssdeep_sorted = get_ssdeep_hash(&imphash_bytes_ordered)?;
    Ok((imphashes, total_dlls, imports.len()))
}

fn parse_pe_exports(exports: &Vec<goblin::pe::export::Export>) -> io::Result<Exports> {
    let mut exps = Exports::default();
    let mut exphash_text = String::new();
    for e in exports.iter() {
        exps.names.push(e.name.unwrap_or("").to_string());
        let mut temp = String::new();
        temp.push_str(&e.name.unwrap_or("").to_string());
        temp.push_str(",");
        exphash_text.push_str(&temp.to_string());
    }
    exps.count = exports.len();
    let mut exphashes = ExpHashes::default();
    exphash_text = exphash_text.trim_end_matches(",").to_string();
    exphashes.md5 = format!("{:x}", md5::compute(exphash_text.clone())).to_lowercase();
    let exphash_bytes: Vec<u8> = exphash_text.as_bytes().to_vec();
    exphashes.ssdeep = get_ssdeep_hash(&exphash_bytes)?;
    exps.hashes = exphashes;
    Ok(exps)
}

pub fn get_pe(buffer: &[u8], path: &Path) -> Binary {
    let mut bin = Binary::default();
    if let Ok(pe) = pe::PE::parse(&buffer) {
        (bin.imports, bin.binary_info.is_dotnet) = parse_pe_imports(&pe.imports).unwrap();
        bin.binary_info.entry_point = format!("0x{:x}", pe.entry);
        bin.sections = get_sections(&pe, path).unwrap();
        (bin.imports.hashes, bin.imports.lib_count, bin.imports.func_count) = get_imphashes(&pe.imports).unwrap();
        bin.binary_info.is_64 = pe.is_64;
        bin.binary_info.is_lib = pe.is_lib;
        bin.exports = parse_pe_exports(&pe.exports).unwrap();
        get_pe_file_info(path, &mut bin.binary_info).unwrap();
        bin.binary_info.format = BinaryFormat::Pe;
        bin.binary_info.arch = get_arch(pe.header.coff_header.machine);
        bin.binary_info.pe_info.timestamps.compile = get_date_string(pe.header.coff_header.time_date_stamp as i64).unwrap();
        bin.binary_info.pe_info.linker.major_version = match pe.header.optional_header {
            Some(d) => d.standard_fields.major_linker_version,
            None => 0
        };
        bin.binary_info.pe_info.linker.minor_version = match pe.header.optional_header {
            Some(d) => d.standard_fields.minor_linker_version,
            None => 0
        };
    }
    bin
}
