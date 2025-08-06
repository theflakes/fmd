use crate::data_defs::{BinSection, BinSections, Binary, BinaryFormat, BinaryInfo, MachOInfo, ExpHashes, Exports, Function, ImpHashes, Import, Imports, Architecture};
use goblin::mach::{self, cputype, header, Mach};
use std::collections::HashMap;
use fuzzyhash::FuzzyHash;
use entropy::shannon_entropy;
use std::str;

fn get_arch(cputype: u32) -> Architecture {
    match cputype {
        cputype::CPU_TYPE_X86_64 => Architecture::X86_64,
        cputype::CPU_TYPE_X86 => Architecture::X86,
        cputype::CPU_TYPE_ARM => Architecture::Arm,
        cputype::CPU_TYPE_ARM64 => Architecture::AArch64,
        cputype::CPU_TYPE_POWERPC => Architecture::PowerPC,
        _ => Architecture::Unknown,
    }
}

fn parse_macho_header_info(macho: &mach::MachO, binary_info: &mut BinaryInfo) {
    binary_info.is_64 = macho.is_64;
    binary_info.entry_point = format!("0x{:x}", macho.entry);
    binary_info.is_lib = macho.header.filetype == header::MH_DYLIB;
    binary_info.macho_info.file_type = header::filetype_to_str(macho.header.filetype).to_string();
    binary_info.macho_info.flags = format!("{:?}", macho.header.flags);
    binary_info.macho_info.cpu_subtype = cputype::get_arch_name_from_types(macho.header.cputype, macho.header.cpusubtype).unwrap_or("UNKNOWN").to_string();
    binary_info.macho_info.ncmds = macho.header.ncmds as u32;
    binary_info.macho_info.sizeofcmds = macho.header.sizeofcmds as u32;
    binary_info.format = BinaryFormat::MachO;
    binary_info.arch = get_arch(macho.header.cputype);
}

fn parse_macho_sections(macho: &mach::MachO, buffer: &[u8]) -> BinSections {
    let mut sections = BinSections::default();
    for segment in &macho.segments {
        if let Ok(sections_data) = segment.sections() {
            for (section, _) in sections_data {
                let segname = str::from_utf8(&section.segname).unwrap_or("");
                let sectname = str::from_utf8(&section.sectname).unwrap_or("");
                let mut bin_section = BinSection::default();
                bin_section.name = format!("{}.{}", segname, sectname);
                let start = section.offset as usize;
                let end = (section.offset + section.size as u32) as usize;
                if end <= buffer.len() {
                    let section_data = &buffer[start..end];
                    bin_section.raw_size = section.size as u32;
                    bin_section.virt_size = section.size as u32;
                    bin_section.entropy = shannon_entropy(section_data);
                    bin_section.md5 = format!("{:x}", md5::compute(section_data)).to_lowercase();
                    bin_section.ssdeep = FuzzyHash::new(section_data).to_string();
                }
                bin_section.virt_address = format!("0x{:x}", section.addr);
                sections.sections.push(bin_section);
            }
        }
    }
    sections.total_sections = macho.segments.iter().map(|s| s.nsects).sum::<u32>() as u16;
    sections.total_raw_bytes = macho.segments.iter().map(|s| s.filesize).sum::<u64>() as u32;
    sections.total_virt_bytes = macho.segments.iter().map(|s| s.vmsize).sum::<u64>() as u32;
    return sections
}

fn get_hash_sorted(hash_array: &mut Vec<String>) -> (String, String) {
    hash_array.sort();
    let mut imphash_text_sorted = String::new();
    for i in hash_array.iter() {
        imphash_text_sorted.push_str(i);
    }
    imphash_text_sorted = imphash_text_sorted.trim_end_matches(",").to_string();
    let imphash_sorted = format!("{:x}", md5::compute(&imphash_text_sorted)).to_lowercase();

    return (imphash_text_sorted, imphash_sorted)
}

fn get_macho_imphashes(imports: &Imports) -> ImpHashes {
    let mut imphash_array: Vec<String> = Vec::new();
    let mut imphash_text = String::new();

    for imp_lib in &imports.imports {
        let so = imp_lib.lib.to_lowercase();

        for func in &imp_lib.names {
            let mut temp = String::new();
            temp.push_str(&so);
            temp.push_str(".");
            temp.push_str(&func.name.to_lowercase());
            temp.push_str(",");
            imphash_text.push_str(&temp);
            imphash_array.push(temp);
        }
    }

    let mut imphashes = ImpHashes::default();
    imphash_text = imphash_text.trim_end_matches(",").to_string();
    imphashes.md5 = format!("{:x}", md5::compute(imphash_text.as_bytes())).to_lowercase();
    
    let (imphash_text_sorted, md5_sorted) = get_hash_sorted(&mut imphash_array);
    imphashes.md5_sorted = md5_sorted;

    imphashes.ssdeep = FuzzyHash::new(imphash_text.as_bytes()).to_string();
    imphashes.ssdeep_sorted = FuzzyHash::new(imphash_text_sorted.as_bytes()).to_string();

    return imphashes
}

fn get_macho_exphashes(exports: &Exports) -> ExpHashes {
    let mut exphashes = ExpHashes::default();
    let mut exphash_array: Vec<String> = Vec::new();
    let mut exphash_text = String::new();

    for name in &exports.names {
        let lower_name = name.to_lowercase();
        exphash_text.push_str(&lower_name);
        exphash_text.push_str(",");
        exphash_array.push(lower_name);
    }

    exphash_text = exphash_text.trim_end_matches(",").to_string();
    exphashes.md5 = format!("{:x}", md5::compute(exphash_text.as_bytes())).to_lowercase();
    
    let (exphash_text_sorted, md5_sorted) = get_hash_sorted(&mut exphash_array);
    exphashes.md5_sorted = md5_sorted;

    exphashes.ssdeep = FuzzyHash::new(exphash_text.as_bytes()).to_string();
    exphashes.ssdeep_sorted = FuzzyHash::new(exphash_text_sorted.as_bytes()).to_string();

    return exphashes
}

fn parse_macho_imports(macho: &mach::MachO) -> Imports {
    let mut imports = Imports::default();
    if let Ok(imports_data) = macho.imports() {
        for import in imports_data {
            if let Some(existing_import) = imports.imports.iter_mut().find(|i| i.lib == import.dylib) {
                existing_import.names.push(Function {
                    name: import.name.to_string(),
                    ..Default::default()
                });
                existing_import.count += 1;
            } else {
                imports.imports.push(Import {
                    lib: import.dylib.to_string(),
                    count: 1,
                    names: vec![Function {
                        name: import.name.to_string(),
                        ..Default::default()
                    }],
                });
            }
        }
    }
    imports.func_count = imports.imports.iter().map(|i| i.names.len()).sum();
    imports.lib_count = imports.imports.len();
    imports.hashes = get_macho_imphashes(&imports);
    return imports
}

fn parse_macho_exports(macho: &mach::MachO) -> Exports {
    let mut exports = Exports::default();
    if let Ok(exports_data) = macho.exports() {
        for export in exports_data {
            exports.names.push(export.name.to_string());
        }
    }
    exports.count = exports.names.len();
    exports.hashes = get_macho_exphashes(&exports);
    return exports
}

pub fn get_macho(buffer: &[u8]) -> Binary {
    let mut bin = Binary::default();
    if let Ok(Mach::Binary(macho)) = Mach::parse(buffer) {
        parse_macho_header_info(&macho, &mut bin.binary_info);
        bin.sections = parse_macho_sections(&macho, buffer);
        bin.imports = parse_macho_imports(&macho);
        bin.exports = parse_macho_exports(&macho);
    }
    return bin
}