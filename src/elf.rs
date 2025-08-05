use goblin::elf;
use crate::data_defs::{Binary, BinSection, BinSections, Imports, Exports, Import, Function, BinaryInfo, ElfInfo};
use std::collections::HashMap;


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


pub fn get_elf(buffer: &[u8]) -> Binary {
    let mut bin = Binary::default();
    if let Ok(elf) = elf::Elf::parse(buffer) {
        bin.binary_info.is_64 = elf.is_64;
        bin.binary_info.entry_point = format!("0x{:02x}", elf.entry);
        bin.binary_info.is_lib = elf.header.e_type == elf::header::ET_DYN;

        // Populate BinaryInfo for ELF
        bin.binary_info.elf_info.os_abi = format!("{:?}", elf.header.e_ident[elf::header::EI_OSABI]);
        bin.binary_info.elf_info.abi_version = elf.header.e_ident[elf::header::EI_ABIVERSION];
        bin.binary_info.elf_info.file_type = get_elf_file_type_name(elf.header.e_type);
        bin.binary_info.elf_info.object_version = elf.header.e_version as u8;
        bin.binary_info.is_elf = true;

        let mut sections = BinSections::default();
        for sh in &elf.section_headers {
            let mut section = BinSection::default();
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                section.name = name.to_string();
            }
            section.raw_size = sh.sh_size as u32;
            section.virt_size = sh.sh_size as u32;
            section.virt_address = format!("0x{:02x}", sh.sh_addr);
            sections.sections.push(section);
        }
        sections.total_sections = elf.section_headers.len() as u16;
        bin.sections = sections;

        let mut imports = Imports::default();
        let mut exports = Exports::default();

        // 1. Build a map from version index to library name.
        let mut version_map: HashMap<u16, &str> = HashMap::new();
        if let Some(verneed_iter) = &elf.verneed {
            for r in verneed_iter.iter() {
                if let Some(lib_name) = elf.dynstrtab.get_at(r.vn_file) {
                    for aux in r.iter() {
                        version_map.insert(aux.vna_other, lib_name);
                    }
                }
            }
        }

        // 2. Iterate through symbols and link them.
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if sym.is_import() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    // 3. Find the library name using the version map.
                    let lib_name = elf.versym
                        .as_ref()
                        .and_then(|vs| vs.get_at(i))
                        .and_then(|versym| version_map.get(&versym.vs_val))
                        .map(|s| *s)
                        .unwrap_or_else(|| {
                            // Fallback for symbols without version info (e.g. from older linkers)
                            if elf.libraries.len() == 1 {
                                elf.libraries[0]
                            } else {
                                "unknown"
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
            } else if sym.st_bind() == elf::sym::STB_GLOBAL && sym.st_shndx as u32 != elf::section_header::SHN_UNDEF {
                 if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        exports.names.push(name.to_string());
                    }
                }
            }
        }

        imports.func_count = imports.imports.iter().map(|i| i.names.len()).sum();
        imports.lib_count = imports.imports.len();
        exports.count = exports.names.len();
        bin.imports = imports;
        bin.exports = exports;
    }
    bin
}