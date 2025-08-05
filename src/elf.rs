use goblin::elf;
use crate::data_defs::{Binary, BinSection, BinSections, Imports, Exports, Import, Function, BinaryInfo, ElfInfo, ImpHashes, ExpHashes};
use std::collections::HashMap;
use fuzzyhash::FuzzyHash;

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

fn parse_elf_header_info(elf: &elf::Elf, binary_info: &mut BinaryInfo) {
    binary_info.is_64 = elf.is_64;
    binary_info.entry_point = format!("0x{:02x}", elf.entry);
    binary_info.is_lib = elf.header.e_type == elf::header::ET_DYN;
    binary_info.elf_info.os_abi = format!("{:?}", elf.header.e_ident[elf::header::EI_OSABI]);
    binary_info.elf_info.abi_version = elf.header.e_ident[elf::header::EI_ABIVERSION];
    binary_info.elf_info.file_type = get_elf_file_type_name(elf.header.e_type);
    binary_info.elf_info.object_version = elf.header.e_version as u8;
    binary_info.is_elf = true;
}

fn parse_elf_sections(elf: &elf::Elf) -> BinSections {
    let mut sections = BinSections::default();
    for sh in &elf.section_headers {
        let mut section = BinSection::default();
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            section.name = name.to_string();
        }
        if sh.sh_type == elf::section_header::SHT_NOBITS {
            section.raw_size = 0;
            section.virt_size = sh.sh_size as u32;
            sections.total_virt_bytes += sh.sh_size as u32;
        } else {
            section.raw_size = sh.sh_size as u32;
            section.virt_size = sh.sh_size as u32;
            sections.total_raw_bytes += sh.sh_size as u32;
            sections.total_virt_bytes += sh.sh_size as u32;
        }
        section.virt_address = format!("0x{:02x}", sh.sh_addr);
        sections.sections.push(section);
    }
    sections.total_sections = elf.section_headers.len() as u16;
    sections
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
    version_map
}

fn get_hash_sorted(hash_array: &mut Vec<String>) -> (String, String) {
    hash_array.sort();
    let mut imphash_text_sorted = String::new();
    for i in hash_array.iter() {
        imphash_text_sorted.push_str(i);
    }
    imphash_text_sorted = imphash_text_sorted.trim_end_matches(",").to_string();
    let imphash_sorted = format!("{:x}", md5::compute(&imphash_text_sorted)).to_lowercase();

    (imphash_text_sorted, imphash_sorted)
}

fn get_elf_imphashes(imports: &Imports) -> ImpHashes {
    let mut imphash_array: Vec<String> = Vec::new();
    let mut imphash_text = String::new();

    for imp_lib in &imports.imports {
        let dll = imp_lib.lib.to_lowercase()
            .replace(".dll", "")
            .replace(".sys", "")
            .replace(".drv", "")
            .replace(".ocx", "");

        for func in &imp_lib.names {
            let mut temp = String::new();
            temp.push_str(&dll);
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

    imphashes
}

fn get_elf_exphashes(exports: &Exports) -> ExpHashes {
    let mut exphashes = ExpHashes::default();
    let mut exphash_text = String::new();

    for name in &exports.names {
        exphash_text.push_str(&name.to_lowercase());
        exphash_text.push_str(",");
    }

    exphash_text = exphash_text.trim_end_matches(",").to_string();
    exphashes.md5 = format!("{:x}", md5::compute(exphash_text.as_bytes())).to_lowercase();
    exphashes.ssdeep = FuzzyHash::new(exphash_text.as_bytes()).to_string();

    exphashes
}

fn parse_elf_imports(elf: &elf::Elf, version_map: &HashMap<u16, String>) -> Imports {
    let mut imports = Imports::default();
    for (i, sym) in elf.dynsyms.iter().enumerate() {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
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

                if let Some(import) = imports.imports.iter_mut().find(|i| i.lib == lib_name) {
                    import.names.push(Function {
                        name: name.to_string(),
                        ..Default::default()
                    });
                    import.count += 1;
                } else {
                    imports.imports.push(Import {
                        lib: lib_name.to_string(),
                        count: 1,
                        names: vec![Function {
                            name: name.to_string(),
                            ..Default::default()
                        }],
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
    exports
}

pub fn get_elf(buffer: &[u8]) -> Binary {
    let mut bin = Binary::default();
    if let Ok(elf) = elf::Elf::parse(buffer) {
        parse_elf_header_info(&elf, &mut bin.binary_info);
        bin.sections = parse_elf_sections(&elf);
        let version_map = build_elf_version_map(&elf);
        bin.imports = parse_elf_imports(&elf, &version_map);
        bin.exports = parse_elf_exports(&elf);
    }
    bin
}
