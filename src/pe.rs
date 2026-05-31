use crate::data_defs::{
    get_hash_sorted, is_function_interesting, Architecture, BinSection, BinSections, Binary,
    BinaryFormat, BinaryInfo, ExpHashes, Exports, Function, ImpHashes, Import, Imports,
};
use crate::ordinals;
use anyhow::Result;
use entropy::shannon_entropy;
use exe;
use fuzzyhash::FuzzyHash;
use goblin::pe;
use std::path::Path;

fn get_arch(machine: u16) -> Architecture {
    match machine {
        pe::header::COFF_MACHINE_X86_64 => Architecture::X86_64,
        pe::header::COFF_MACHINE_X86 => Architecture::X86,
        pe::header::COFF_MACHINE_ARM => Architecture::Arm,
        pe::header::COFF_MACHINE_ARM64 => Architecture::AArch64,
        pe::header::COFF_MACHINE_ARMNT => Architecture::Arm,
        pe::header::COFF_MACHINE_THUMB => Architecture::Arm,
        pe::header::COFF_MACHINE_MIPS16 => Architecture::Mips,
        pe::header::COFF_MACHINE_MIPSFPU => Architecture::Mips,
        pe::header::COFF_MACHINE_MIPSFPU16 => Architecture::Mips,
        pe::header::COFF_MACHINE_RISCV32 => Architecture::RiscV,
        pe::header::COFF_MACHINE_RISCV64 => Architecture::RiscV,
        pe::header::COFF_MACHINE_RISCV128 => Architecture::RiscV,
        pe::header::COFF_MACHINE_POWERPC => Architecture::PowerPC,
        pe::header::COFF_MACHINE_IA64 => Architecture::Itanium,
        _ => Architecture::Unknown,
    }
}

fn get_ssdeep_hash(buffer: &[u8]) -> Result<String> {
    let ssdeep = FuzzyHash::new(buffer);
    Ok(ssdeep.to_string())
}

fn get_pe_file_info(path: &Path, binary_info: &mut BinaryInfo) -> Result<()> {
    let Ok(pefile) = exe::VecPE::from_disk_file(path) else {
        return Ok(());
    };
    let Ok(vs_version_check) = exe::VSVersionInfo::parse(&pefile) else {
        return Ok(());
    };
    let vs_version = vs_version_check;
    if let Some(string_file_info) = vs_version.string_file_info {
        let Ok(string_map) = string_file_info.children[0].string_map() else {
            return Ok(());
        };
        binary_info.pe_info.product_version = string_map
            .get("ProductVersion")
            .cloned()
            .unwrap_or_default();
        binary_info.pe_info.original_filename = string_map
            .get("OriginalFilename")
            .cloned()
            .unwrap_or_default();
        binary_info.pe_info.file_description = string_map
            .get("FileDescription")
            .cloned()
            .unwrap_or_default();
        binary_info.pe_info.file_version =
            string_map.get("FileVersion").cloned().unwrap_or_default();
        binary_info.pe_info.product_name =
            string_map.get("ProductName").cloned().unwrap_or_default();
        binary_info.pe_info.company_name =
            string_map.get("CompanyName").cloned().unwrap_or_default();
        binary_info.pe_info.internal_name =
            string_map.get("InternalName").cloned().unwrap_or_default();
        binary_info.pe_info.legal_copyright = string_map
            .get("LegalCopyright")
            .cloned()
            .unwrap_or_default();
    }
    Ok(())
}

fn get_sections(pex: &pe::PE, buffer: &[u8]) -> Result<BinSections> {
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
        let start = s.pointer_to_raw_data as usize;
        let end = start + s.size_of_raw_data as usize;
        // Use slice reference instead of Vec copy (optimization 6)
        let data = buffer.get(start..end).unwrap_or(&[]);
        bs.entropy = shannon_entropy(data);
        bs.md5 = format!("{:x}", md5::compute(data)).to_lowercase();
        bs.ssdeep = get_ssdeep_hash(data)?;
        bss.sections.push(bs);
    }
    Ok(bss)
}

fn is_dotnet(imps: &Imports) -> Result<bool> {
    if imps.imports.len() == 1 {
        if imps.imports[0].count == 1
            && imps.imports[0].lib == "mscoree.dll"
            && (imps.imports[0].names[0].name == "_CorExeMain"
                || imps.imports[0].names[0].name == "_CorDllMain")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_pe_imports(imports: &[goblin::pe::import::Import]) -> Result<(Imports, bool)> {
    // O(n) grouping with HashMap instead of O(n^2) nested loops (optimization 3)
    let mut dll_order: Vec<String> = Vec::new();
    let mut dll_imports: std::collections::HashMap<String, Vec<&goblin::pe::import::Import>> =
        std::collections::HashMap::new();

    for import in imports {
        let dll = import.dll.to_string();
        let list = dll_imports.entry(dll.clone()).or_default();
        if list.is_empty() {
            dll_order.push(dll);
        }
        list.push(import);
    }

    let mut imps: Imports = Imports::default();
    let mut func: Function = Function::default();

    for dll in &dll_order {
        let mut temp = Import::default();
        temp.lib = dll.clone();
        for imp in &dll_imports[dll] {
            temp.count += 1;
            func.name = imp.name.to_string();
            func.info = is_function_interesting(&dll.to_lowercase(), &func.name);
            temp.names.push(func.clone());
        }
        imps.imports.push(temp);
    }

    let is_dot_net = is_dotnet(&imps)?;
    Ok((imps, is_dot_net))
}

fn check_ordinal(dll: &str, func: &str) -> Result<String> {
    let mut f: String = func.to_ascii_lowercase().replace("ordinal ", "");
    if f.parse::<u32>().is_ok() {
        let o = f.parse::<u32>()?;
        f = ordinals::imphash_resolve(dll, o).to_ascii_lowercase();
    }
    Ok(f)
}

fn get_imphashes(imports: &[goblin::pe::import::Import]) -> Result<(ImpHashes, usize, usize)> {
    let mut imphash_array: Vec<String> = Vec::new();
    let mut imphash_text = String::new();
    let mut total_dlls = 0;
    let mut track_dll = String::new();
    for i in imports.iter() {
        let mut temp = String::new();
        if i.dll != track_dll {
            total_dlls += 1;
        }
        let dll = i.dll.to_ascii_lowercase();
        let dll = dll
            .strip_suffix(".dll")
            .or_else(|| dll.strip_suffix(".sys"))
            .or_else(|| dll.strip_suffix(".drv"))
            .or_else(|| dll.strip_suffix(".ocx"))
            .unwrap_or(&dll);
        let dll = dll.to_string();
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
    imphashes.md5 = format!("{:x}", md5::compute(imphash_text.as_bytes())).to_lowercase();
    let (imphash_text_sorted, sorted_md5) = get_hash_sorted(&mut imphash_array);
    imphashes.md5_sorted = sorted_md5;
    // Compute SSdeep directly from bytes — no intermediate Vec needed (optimization 7)
    imphashes.ssdeep = get_ssdeep_hash(imphash_text.as_bytes())?;
    imphashes.ssdeep_sorted = get_ssdeep_hash(imphash_text_sorted.as_bytes())?;
    Ok((imphashes, total_dlls, imports.len()))
}

fn parse_pe_exports(exports: &[goblin::pe::export::Export]) -> Result<Exports> {
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
    exphashes.md5 = format!("{:x}", md5::compute(exphash_text.as_bytes())).to_lowercase();
    exphashes.ssdeep = get_ssdeep_hash(exphash_text.as_bytes())?;
    exps.hashes = exphashes;
    Ok(exps)
}

pub fn get_pe(buffer: &[u8], path: &Path) -> Result<Binary> {
    let mut bin = Binary::default();
    if let Ok(pe) = pe::PE::parse(&buffer) {
        (bin.imports, bin.binary_info.is_dotnet) = parse_pe_imports(&pe.imports)?;
        bin.binary_info.entry_point = format!("0x{:x}", pe.entry);
        bin.sections = get_sections(&pe, buffer)?;
        (
            bin.imports.hashes,
            bin.imports.lib_count,
            bin.imports.func_count,
        ) = get_imphashes(&pe.imports)?;
        bin.binary_info.is_64 = pe.is_64;
        bin.binary_info.is_lib = pe.is_lib;
        bin.exports = parse_pe_exports(&pe.exports)?;
        get_pe_file_info(path, &mut bin.binary_info)?;
        bin.binary_info.format = BinaryFormat::Pe;
        bin.binary_info.arch = get_arch(pe.header.coff_header.machine);
        bin.binary_info.pe_info.timestamps.compile =
            chrono::DateTime::<chrono::Utc>::from_timestamp(
                pe.header.coff_header.time_date_stamp as i64,
                0,
            )
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
            .unwrap_or_default();
        bin.binary_info.pe_info.linker.major_version = match pe.header.optional_header {
            Some(d) => d.standard_fields.major_linker_version,
            None => 0,
        };
        bin.binary_info.pe_info.linker.minor_version = match pe.header.optional_header {
            Some(d) => d.standard_fields.minor_linker_version,
            None => 0,
        };
    }
    Ok(bin)
}
