use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze_file_data;
use crate::data_defs::MetaData;

/// Recursively collect all files from a path (file or directory)
pub fn collect_files(path: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        collect_files_recursive(path, max_depth, 1, &mut files);
    }
    files
}

fn collect_files_recursive(
    path: &Path,
    max_depth: usize,
    current_depth: usize,
    files: &mut Vec<PathBuf>,
) {
    // When max_depth == 0, only process files in the current directory
    // (no recursion into subdirectories). Matches sequential behavior.
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries {
            if let Ok(entry) = entry {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    files.push(entry_path);
                } else if entry_path.is_dir() && max_depth > 0 && current_depth < max_depth {
                    collect_files_recursive(&entry_path, max_depth, current_depth + 1, files);
                }
            }
        }
    }
}

/// Run parallel file analysis and print results in sorted order by path
pub fn run_parallel(
    files: Vec<PathBuf>,
    pprint: bool,
    strings_length: usize,
    max_size: u64,
    extensions: &Vec<String>,
    not_exts: bool,
    int_mtypes: bool,
    jobs: usize,
) {
    if files.is_empty() {
        return;
    }

    let num_threads = if jobs > 0 {
        jobs
    } else {
        // Reserve one core for the OS
        std::thread::available_parallelism()
            .map(|c| c.get().saturating_sub(1).max(1))
            .unwrap_or(1)
    };

    eprintln!(
        "Analyzing {} files with {} threads...",
        files.len(),
        num_threads
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("Failed to build thread pool");

    let results: BTreeMap<String, MetaData> = pool.install(|| {
        files
            .into_par_iter()
            .filter_map(|path| {
                analyze_file_data(
                    &path,
                    strings_length,
                    max_size,
                    extensions,
                    not_exts,
                    int_mtypes,
                )
                .ok()
                .map(|data| (path.to_string_lossy().into_owned(), data))
            })
            .collect()
    });

    eprintln!("Analyzed {} files, printing results...", results.len());

    for (_, metadata) in results {
        if pprint {
            metadata.report_pretty_log();
        } else {
            metadata.report_log();
        }
    }
}
