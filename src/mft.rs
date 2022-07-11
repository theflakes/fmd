use crate::{data_defs, sector_reader};

use std::{io, str};
use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{
    NtfsAttributeList, NtfsFileName, NtfsFileNamespace, NtfsStandardInformation,
};
use ntfs::{Ntfs, NtfsAttribute, NtfsAttributeType, NtfsFile, NtfsReadSeek, NtfsTime};
use std::io::{BufReader, Read, Seek, Write};
use sector_reader::SectorReader;
use data_defs::FileTimestamps;
use anyhow::{anyhow, bail, Context, Result};
use epochs::windows_file;
use is_elevated::is_elevated;
use std::fs::{self, File};

struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    current_directory: Vec<NtfsFile<'n>>,
    current_directory_string: String,
    fs: T,
    ntfs: &'n Ntfs,
}


fn fileinfo_filename<T>(info: &mut CommandInfo<T>, attribute: NtfsAttribute) -> io::Result<(FileTimestamps)>
where
    T: Read + Seek,
{
    let mut ftimes = FileTimestamps::default();
    let file_name = attribute.structured_value::<_, NtfsFileName>(&mut info.fs)?;
    ftimes.access_fn = windows_file(file_name.access_time().nt_timestamp() as i64).unwrap().format("%Y-%m-%dT%H:%M:%S.%3f").to_string();
    ftimes.create_fn = windows_file(file_name.creation_time().nt_timestamp() as i64).unwrap().format("%Y-%m-%dT%H:%M:%S.%3f").to_string();
    ftimes.modify_fn = windows_file(file_name.modification_time().nt_timestamp() as i64).unwrap().format("%Y-%m-%dT%H:%M:%S.%3f").to_string();
    ftimes.mft_record = windows_file(file_name.mft_record_modification_time().nt_timestamp() as i64).unwrap().format("%Y-%m-%dT%H:%M:%S.%3f").to_string();
    Ok(ftimes)
}


pub fn get_fname(file_path: &String) -> Result<(FileTimestamps, bool)> {
    let mut ftimes = FileTimestamps::default();
    if !is_elevated() { return Ok((ftimes, false)) }
    let temp: Vec<&str> = file_path.split(":").collect();
    let dirs = temp[1].split("\\");
    let filename = file_path.split("\\").last().unwrap();
    let root = r"\\.\".to_owned() + temp[0] + r":";
    // if we are not accessing an NTFS filesystem lets retrun gracefully
    let f = match File::open(root) {
        Ok(it) => it,
        Err(err) => return Ok((ftimes, true)),
    };
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let mut ntfs = Ntfs::new(&mut fs)?;
    ntfs.read_upcase_table(&mut fs)?;
    let current_directory = vec![ntfs.root_directory(&mut fs)?];
    let mut info = CommandInfo {
        current_directory,
        current_directory_string: String::new(),
        fs,
        ntfs: &ntfs,
    };
    for dir in dirs {
        cd(dir, &mut info);
    }
    let file = parse_file_arg(filename, &mut info)?;
    let mut attributes = file.attributes();
    while let Some(attribute_item) = attributes.next(&mut info.fs) {
        let attribute_item = attribute_item?;
        let attribute = attribute_item.to_attribute();

        match attribute.ty() {
            Ok(NtfsAttributeType::StandardInformation) => continue,
            Ok(NtfsAttributeType::FileName) => {
                ftimes = fileinfo_filename(&mut info, attribute)?;
                break;
            },
            Ok(NtfsAttributeType::Data) => continue,
            _ => continue,
        }
    }
    Ok((ftimes, true))
}


fn cd<T>(arg: &str, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    let index = info
        .current_directory
        .last()
        .unwrap()
        .directory_index(&mut info.fs)?;
    let mut finder = index.finder();
    let maybe_entry = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg);

    if maybe_entry.is_none() {
        return Ok(());
    }

    let entry = maybe_entry.unwrap()?;
    let file_name = entry
        .key()
        .expect("key must exist for a found Index Entry")?;

    if !file_name.is_directory() {
        return Ok(());
    }

    let file = entry.to_file(info.ntfs, &mut info.fs)?;
    let file_name = best_file_name(
        info,
        &file,
        info.current_directory.last().unwrap().file_record_number(),
    )?;
    if !info.current_directory_string.is_empty() {
        info.current_directory_string += "\\";
    }
    info.current_directory_string += &file_name.name().to_string_lossy();

    info.current_directory.push(file);

    Ok(())
}


fn best_file_name<T>(
    info: &mut CommandInfo<T>,
    file: &NtfsFile,
    parent_record_number: u64,
) -> Result<NtfsFileName>
where
    T: Read + Seek,
{
    // Try to find a long filename (Win32) first.
    // If we don't find one, the file may only have a single short name (Win32AndDos).
    // If we don't find one either, go with any namespace. It may still be a Dos or Posix name then.
    let priority = [
        Some(NtfsFileNamespace::Win32),
        Some(NtfsFileNamespace::Win32AndDos),
        None,
    ];

    for match_namespace in priority {
        if let Some(file_name) =
            file.name(&mut info.fs, match_namespace, Some(parent_record_number))
        {
            let file_name = file_name?;
            return Ok(file_name);
        }
    }

    bail!(
        "Found no FileName attribute for File Record {:#x}",
        file.file_record_number()
    )
}


fn parse_file_arg<'n, T>(arg: &str, info: &mut CommandInfo<'n, T>) -> Result<NtfsFile<'n>>
where
    T: Read + Seek,
{
    if arg.is_empty() {
        bail!("Missing argument!");
    }

    if let Some(record_number_arg) = arg.strip_prefix("/") {
        let record_number = match record_number_arg.strip_prefix("0x") {
            Some(hex_record_number_arg) => u64::from_str_radix(hex_record_number_arg, 16),
            None => u64::from_str_radix(record_number_arg, 10),
        };

        if let Ok(record_number) = record_number {
            let file = info.ntfs.file(&mut info.fs, record_number)?;
            Ok(file)
        } else {
            bail!(
                "Cannot parse record number argument \"{}\"",
                record_number_arg
            )
        }
    } else {
        let index = info
            .current_directory
            .last()
            .unwrap()
            .directory_index(&mut info.fs)?;
        let mut finder = index.finder();

        if let Some(entry) = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg) {
            let entry = entry?;
            let file = entry.to_file(info.ntfs, &mut info.fs)?;
            Ok(file)
        } else {
            bail!("No such file or directory \"{}\".", arg)
        }
    }
}