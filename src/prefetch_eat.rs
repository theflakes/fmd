//! Resolve prefetch block-offset traces to DLL EAT function names.
//!
//! When analysing a Windows prefetch artifact this module:
//! 1. Cleans the prefetch volume-prefixed path (e.g., `\\VOLUME{...}\\...`)
//! 2. Attempts to load the file directly from the prefetch record or `SystemRoot`
//! 3. Falls back to system directories using the exact filename provided
//! 4. Validates the file as a PE binary via **goblin** (MZ/PE header check) regardless of extension
//! 5. Maps export RVAs to specific sub-sectors of the page using the `used` bitmask

use crate::data_defs::PrefetchTrace;
use goblin::pe::PE;
use std::collections::HashMap;
use std::path::Path;

const PAGE_SIZE: u64 = 4096;
const SECTOR_COUNT: usize = 8; // A typical prefetch trace block's used bitmask tracks 8 chunks/sectors

/// Normalize a dependency name.
pub fn normalize_dll_name(name: &str) -> String {
    let basename = Path::new(name).file_name().unwrap_or_default();
    basename.to_string_lossy().to_lowercase()
}

/// Resolve prefetch traces to binary export function names by verifying both
/// the 4KB page range and whether the specific sub-sector bit is active in `used`.
/// Treats any matching file as a valid PE binary if its header checks out, skipping stem searches.
pub fn resolve_prefetch_to_dll_funcs(
    filename: &str,
    traces: &[PrefetchTrace],
    _dll_name_strict: &str,
    target_name_lower: &str,
) -> Option<HashMap<u32, Vec<String>>> {
    // Strip the \\VOLUME{...} prefix if present so we can evaluate a clean relative path
    let cleaned_path = if filename.starts_with("\\\\VOLUME") {
        if let Some(idx) = filename.find("}\\") {
            &filename[idx + 2..]
        } else {
            filename
        }
    } else {
        filename
    };

    // Attempt loading directly via the prefetch record paths or exact filename match in System32/SysWOW64
    let file_bytes = std::fs::read(filename)
        .or_else(|_| std::fs::read(cleaned_path))
        .or_else(|_| {
            let windir = std::env::var("SystemRoot")
                .or_else(|_| std::env::var("windir"))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
            let resolved_sys_path = format!("{windir}\\{cleaned_path}");
            std::fs::read(resolved_sys_path)
        })
        .or_else(|_| {
            let exact_path = find_file_on_disk_exact(target_name_lower).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "File not found on disk")
            })?;
            std::fs::read(exact_path)
        })
        .ok()?;

    // Validate the PE headers (MZ / PE signature check via goblin) regardless of file extension
    let pe = PE::parse(&file_bytes).ok()?;

    // Collect all valid exports with their RVAs and names
    let mut exports_list = Vec::new();
    for export in &pe.exports {
        if let Some(name) = export.name.as_ref() {
            exports_list.push((export.rva as u64, name.to_string()));
        }
    }

    let mut result: HashMap<u32, Vec<String>> = HashMap::new();

    for trace in traces {
        // Parse the binary "used" bitfield string (e.g., "11111110")
        let used_bits = parse_used_bitfield(&trace.used);
        if used_bits == 0 {
            continue; // No activity recorded in this trace block
        }

        let block_start_rva = (trace.block_offset as u64) * PAGE_SIZE;
        let sector_size = PAGE_SIZE / (SECTOR_COUNT as u64); // 512 bytes per sector chunk

        let mut matched_funcs = Vec::new();

        // Evaluate each sector bit in the used bitmask
        for sector_idx in 0..SECTOR_COUNT {
            let bit_mask = 1 << sector_idx;
            if (used_bits & bit_mask) != 0 {
                let sector_start_rva = block_start_rva + (sector_idx as u64 * sector_size);
                let sector_end_rva = sector_start_rva + sector_size;

                // Only pull functions whose RVAs land inside this active sector window
                for (rva, name) in &exports_list {
                    if *rva >= sector_start_rva && *rva < sector_end_rva {
                        if !matched_funcs.contains(name) {
                            matched_funcs.push(name.clone());
                        }
                    }
                }
            }
        }

        if !matched_funcs.is_empty() {
            result.insert(trace.block_offset, matched_funcs);
        }
    }

    (!result.is_empty()).then_some(result)
}

/// Parse the "used" bitfield string from a prefetch trace as a binary bitmask.
fn parse_used_bitfield(s: &str) -> u32 {
    u32::from_str_radix(s.trim(), 2).unwrap_or(0)
}

/// Search common Windows system directories for an exact filename match (no stem/extension substitution).
fn find_file_on_disk_exact(name_lower: &str) -> Option<String> {
    let windir = std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .ok()?;

    let candidates: [&str; 3] = ["System32", "SysWOW64", "SYSnative"];

    for &sub in &candidates {
        let candidate = format!("{windir}\\{sub}\\{name_lower}");
        if Path::new(&candidate).exists() {
            return Some(candidate);
        }
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(name_lower);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }

    None
}
