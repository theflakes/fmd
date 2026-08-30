use crate::data_defs::{
    Prefetch, PrefetchDependency, PrefetchNtfsFile, PrefetchTrace, PrefetchVolume,
};
use crate::prefetch_eat;
use anyhow::Result;
use forensic_rs::prelude::*;
use frnsc_prefetch::common::PrefetchFile;
use frnsc_prefetch::prefetch::read_prefetch_file;
use std::path::Path;

// Convert a Windows filetime (100ns ticks since 1601-01-01) into the
// same ISO8601 format used by the rest of this tool
fn filetime_to_iso(ft: &Filetime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
        ft.year(),
        ft.month(),
        ft.day(),
        ft.hour(),
        ft.minute(),
        ft.second(),
        ft.nanoseconds() / 1_000_000
    )
}

fn filetime_u64_to_iso(t: u64) -> String {
    filetime_to_iso(&Filetime::new(t))
}

fn map_prefetch(pf: &PrefetchFile) -> Prefetch {
    let volumes: Vec<PrefetchVolume> = pf
        .volume
        .iter()
        .map(|v| PrefetchVolume {
            device_path: v.device_path.clone(),
            serial_number: v.serial_number,
            creation_time: filetime_u64_to_iso(v.creation_time),
            file_references: v
                .file_references
                .iter()
                .map(|f| PrefetchNtfsFile {
                    mft_entry: f.mft_entry,
                    seq_number: f.seq_number,
                    path: None,
                })
                .collect(),
            directories: v.directory_strings.clone(),
        })
        .collect();

    // The executable's touched files, taken straight from the dependency
    // list to make scanning easier when triaging a cybersecurity event.
    let files: Vec<String> = pf.metrics.iter().map(|m| m.file.clone()).collect();

    Prefetch {
        version: pf.version,
        name: pf.name.clone(),
        run_count: pf.run_count,
        last_run_times: pf.last_run_times.iter().map(filetime_to_iso).collect(),
        dependencies: pf
            .metrics
            .iter()
            .map(|m| PrefetchDependency {
                file: m.file.clone(),
                flags: m.flags.to_string(),
                blocks_to_prefetch: m.blocks_to_prefetch,
                traces: m
                    .traces
                    .iter()
                    .map(|t| PrefetchTrace {
                        flags: t.flags.to_string(),
                        block_offset: t.block_offset,
                        used: format!("{:08b}", t.used_bitfield),
                        prefetched: format!("{:08b}", t.prefetched_bitfield),
                        functions: Vec::new(),
                    })
                    .collect(),
            })
            .collect(),
        files,
        volumes,
    }
}

fn map_prefetch_with_eat(pf: &PrefetchFile) -> Prefetch {
    let mut prefetch = map_prefetch(pf);

    // Resolve block offsets to DLL functions where the DLL is found on disk.
    for dependency in prefetch.dependencies.iter_mut() {
        let dll_name_strict: String = prefetch_eat::normalize_dll_name(&dependency.file);
        let dll_name_lower = dll_name_strict.to_lowercase();

        // Only resolve DLLs (pe, sys, drv)
        if !dll_name_lower.ends_with(".dll")
            && !dll_name_lower.ends_with(".sys")
            && !dll_name_lower.ends_with(".drv")
        {
            continue;
        }

        // Try to find the DLL on disk
        if let Some(eat_functions) = prefetch_eat::resolve_prefetch_to_dll_funcs(
            &dependency.file,
            &dependency.traces,
            &dll_name_strict,
            &dll_name_lower,
        ) {
            for trace in dependency.traces.iter_mut() {
                if let Some(func_list) = eat_functions.get(&trace.block_offset) {
                    trace.functions = func_list.clone();
                }
            }
        }
    }

    prefetch
}

/// Parse a Windows prefetch (.pf) file into the tool's Prefetch log structure.
/// Handles both compressed (Win8+/MAM) and uncompressed prefetch files,
/// and validates the embedded executable name and prefetch hash against the
/// artifact name when the file ends in .pf.
pub fn get_prefetch(artifact_name: &str, path: &Path) -> Result<Prefetch> {
    let mut fs = StdVirtualFS::new();
    let file = fs
        .open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open prefetch file: {e}"))?;
    let pf = read_prefetch_file(artifact_name, file)
        .map_err(|e| anyhow::anyhow!("Failed to parse prefetch file: {e}"))?;
    Ok(map_prefetch_with_eat(&pf))
}

/// Quick sniff of the first bytes of a buffer to detect a prefetch file.
/// Matches both the compressed (Win8+) "MAM" signature and the
/// uncompressed version + "SCCA" signature used by versions 17/23/26/30/31.
pub fn is_prefetch_file(buffer: &[u8]) -> bool {
    if buffer.len() < 8 {
        return false;
    }
    // Compressed (Win8+) prefetch: signature 'MAM\0' in the low 24 bits of
    // the first u32 (upper bits hold CRC presence and compression algorithm)
    let first = u32::from_le_bytes(buffer[0..4].try_into().unwrap_or([0; 4]));
    if first & 0x00FFFFFF == 0x004D414D {
        return true;
    }
    // Uncompressed prefetch: version u32 followed by signature "SCCA"
    if buffer[4..8] == *b"SCCA" {
        return matches!(first, 17 | 23 | 26 | 30 | 31);
    }
    false
}
