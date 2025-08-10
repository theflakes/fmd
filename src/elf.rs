use goblin::elf;
use crate::data_defs::{BinSection, BinSections, Binary, BinaryFormat, BinaryInfo, 
                    ElfInfo, ExpHashes, Exports, Function, ImpHashes, Import, 
                    Imports, Architecture, is_function_interesting};
use std::collections::HashMap;
use fuzzyhash::FuzzyHash;
use entropy::shannon_entropy;

fn bytes_to_human_readable_string(data: &[u8]) -> String {
    data.iter().map(|&byte| {
        if byte >= 0x20 && byte <= 0x7E {
            byte as char
        } else {
            ' '
        }
    }).collect()
}

fn get_elf_file_type_name(e_type: u16) -> String {
    match e_type {
        elf::header::ET_NONE => "ET_NONE".to_string(),
        elf::header::ET_REL => "ET_REL".to_string(),
        elf::header::ET_EXEC => "ET_EXEC".to_string(),
        elf::header::ET_DYN => "ET_DYN".to_string(),
        elf::header::ET_CORE => "ET_CORE".to_string(),
        _ => format!("UNKNOWN_ET_TYPE({})", e_type),
    }
}

fn get_arch(e_machine: u16) -> Architecture {
    match e_machine {
        elf::header::EM_X86_64 => Architecture::X86_64,
        elf::header::EM_386 => Architecture::X86,
        elf::header::EM_ARM => Architecture::Arm,
        elf::header::EM_AARCH64 => Architecture::AArch64,
        elf::header::EM_MIPS => Architecture::Mips,
        elf::header::EM_PPC => Architecture::PowerPC,
        elf::header::EM_RISCV => Architecture::RiscV,
        elf::header::EM_IA_64 => Architecture::Itanium,
        _ => Architecture::Unknown,
    }
}

fn parse_elf_header_info(elf: &elf::Elf, binary_info: &mut BinaryInfo) {
    binary_info.is_64 = elf.is_64;
    binary_info.entry_point = format!("0x{:x}", elf.entry);
    binary_info.is_lib = elf.header.e_type == elf::header::ET_DYN;
    binary_info.elf_info.os_abi = format!("{:?}", elf.header.e_ident[elf::header::EI_OSABI]);
    binary_info.elf_info.abi_version = elf.header.e_ident[elf::header::EI_ABIVERSION];
    binary_info.elf_info.file_type = get_elf_file_type_name(elf.header.e_type);
    binary_info.elf_info.object_version = elf.header.e_version as u8;
    binary_info.format = BinaryFormat::Elf;
    binary_info.arch = get_arch(elf.header.e_machine);
}

fn parse_elf_sections(elf: &elf::Elf, buffer: &[u8]) -> BinSections {
    let mut sections = BinSections::default();
    for sh in &elf.section_headers {
        let mut section = BinSection::default();
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            section.name = name.to_string();
        }
        let section_data_to_hash: Vec<u8>;
        if sh.sh_type == elf::section_header::SHT_NOBITS {
            section.raw_size = 0;
            section.virt_size = sh.sh_size as u32;
            sections.total_virt_bytes += sh.sh_size as u32;
            section_data_to_hash = Vec::new();
        } else {
            section.raw_size = sh.sh_size as u32;
            section.virt_size = sh.sh_size as u32;
            sections.total_raw_bytes += sh.sh_size as u32;
            sections.total_virt_bytes += sh.sh_size as u32;

            let start = sh.sh_offset as usize;
            let end = (sh.sh_offset + sh.sh_size) as usize;
            if end <= buffer.len() {
                section_data_to_hash = buffer[start..end].to_vec();
            } else {
                section_data_to_hash = Vec::new();
            }
        }
        // Calculate MD5 and SSDeep for the determined section data
        section.md5 = format!("{:x}", md5::compute(&section_data_to_hash)).to_lowercase();
        section.ssdeep = FuzzyHash::new(&section_data_to_hash).to_string();
        section.entropy = shannon_entropy(&section_data_to_hash);

        // Capture human-readable content for .comment and .note sections
        if section.name == ".comment" || section.name.starts_with(".note") {
            section.elf_comment_or_note_content = Some(bytes_to_human_readable_string(&section_data_to_hash));
        }

        section.virt_address = format!("0x{:x}", sh.sh_addr);
        sections.sections.push(section);
    }
    sections.total_sections = elf.section_headers.len() as u16;
    return sections
}

fn build_elf_version_map(elf: &elf::Elf) -> HashMap<u16, String> {
    let mut version_map: HashMap<u16, String> = HashMap::new();
    if let Some(verneed_iter) = &elf.verneed {
        for r in verneed_iter.iter() {
            if let Some(lib_name) = elf.dynstrtab.get_at(r.vn_file) {
                for aux in r.iter() {
                    version_map.insert(aux.vna_other, lib_name.to_string());
                }
            }
        }
    }
    return version_map
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

fn get_elf_imphashes(imports: &Imports) -> ImpHashes {
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

fn get_elf_exphashes(exports: &Exports) -> ExpHashes {
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

fn parse_elf_imports(elf: &elf::Elf, version_map: &HashMap<u16, String>) -> Imports {
    let mut imports = Imports::default();

    for (i, sym) in elf.dynsyms.iter().enumerate() {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                // Resolve the providing library (or fall back to “unknown”)
                let lib_name = elf.versym
                    .as_ref()
                    .and_then(|vs| vs.get_at(i))
                    .and_then(|versym| version_map.get(&versym.vs_val))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        if elf.libraries.len() == 1 {
                            elf.libraries[0].to_string()
                        } else {
                            "unknown".to_string()
                        }
                    });

                let (more_interesting, info) = is_function_interesting(
                    &lib_name.to_lowercase(),
                    &name,
                );

                let func = Function {
                    name: name.to_string(),
                    more_interesting,
                    info,
                    ..Default::default()
                };

                if let Some(import) = imports.imports.iter_mut().find(|imp| imp.lib == lib_name) {
                    import.names.push(func);
                    import.count += 1;
                } else {
                    imports.imports.push(Import {
                        lib: lib_name.to_string(),
                        count: 1,
                        names: vec![func],
                    });
                }
            }
        }
    }

    imports.func_count = imports.imports.iter().map(|i| i.names.len()).sum();
    imports.lib_count = imports.imports.len();
    imports.hashes = get_elf_imphashes(&imports);
    imports
}

fn parse_elf_exports(elf: &elf::Elf) -> Exports {
    let mut exports = Exports::default();
    for sym in elf.dynsyms.iter() {
        if sym.st_bind() == elf::sym::STB_GLOBAL && sym.st_shndx as u32 != elf::section_header::SHN_UNDEF {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    exports.names.push(name.to_string());
                }
            }
        }
    }
    exports.count = exports.names.len();
    exports.hashes = get_elf_exphashes(&exports);
    return exports
}

pub fn get_elf(buffer: &[u8]) -> Binary {
    let mut bin = Binary::default();
    if let Ok(elf) = elf::Elf::parse(buffer) {
        parse_elf_header_info(&elf, &mut bin.binary_info);
        bin.sections = parse_elf_sections(&elf, buffer);
        let version_map = build_elf_version_map(&elf);
        bin.imports = parse_elf_imports(&elf, &version_map);
        bin.exports = parse_elf_exports(&elf);
    }
    return bin
}