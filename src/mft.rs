use crate::data_defs::DataRun;
use crate::{data_defs, sector_reader};

use std::path::Path;
use std::{io, str};
use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{
        NtfsFileName, NtfsFileNamespace
    };
use ntfs::{Ntfs, NtfsAttribute, NtfsAttributeType, NtfsFile, NtfsReadSeek,};
use std::io::{BufReader, Read, Seek};
use sector_reader::SectorReader;
use data_defs::FileTimestamps;
use anyhow::{bail, Result};
use epochs::windows_file;
use std::fs::File;


struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    current_directory: Vec<NtfsFile<'n>>,
    current_directory_string: String,
    fs: T,
    ntfs: &'n Ntfs,
}

fn get_fn_times(nt_timestamp: i64) -> String 
{
    let _t = match windows_file(nt_timestamp) {
        Some(t) => return t.format("%Y-%m-%dT%H:%M:%S.%3f").to_string(),
        None => return "".to_string()
    };
}

/*
    Harvest MFT $FILE_NAME dates
*/
fn fileinfo_filename<T>(info: &mut CommandInfo<T>, attribute: NtfsAttribute, ftimes: &mut FileTimestamps)
where
    T: Read + Seek,
{
    //let mut ftimes = FileTimestamps::default();
    let file_name = match attribute.structured_value::<_, NtfsFileName>(&mut info.fs){
        Ok(f) => f,
        Err(_e) => return
    };
    ftimes.access_fn = get_fn_times(file_name.access_time().nt_timestamp() as i64);
    ftimes.create_fn = get_fn_times(file_name.creation_time().nt_timestamp() as i64);
    ftimes.modify_fn = get_fn_times(file_name.modification_time().nt_timestamp() as i64);
    ftimes.mft_record = get_fn_times(file_name.mft_record_modification_time().nt_timestamp() as i64);
}


fn get_fs(root: String) -> Result<BufReader<SectorReader<File>>, io::Error> {
    let f = match File::open(root) {
        Ok(it) => it,
        Err(e) => return Err(e),
    };
    let sr = SectorReader::new(f, 4096)?;
    let fs = BufReader::new(sr);
    Ok(fs)
}


pub fn get_fname(path: &Path, mut ftimes: FileTimestamps) -> Result<(FileTimestamps, Vec<DataRun>)> {
    let mut ads: Vec<DataRun> = Vec::new();
    let file_path = &path.to_string_lossy().to_string();
    let temp: Vec<&str> = file_path.split(":").collect();
    let dirs = temp[1].split("\\");
    let filename = file_path.split("\\").last().unwrap_or("");
    let root = r"\\.\".to_owned() + temp[0] + r":";
    let mut fs = match get_fs(root.clone()) {
        Ok(f) => f,
        Err(_e) => return Ok((ftimes, ads))
    };
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
        _ = cd(dir, &mut info);
    }
    let file = parse_file_arg(filename, &mut info)?;

    let mut fs = match get_fs(root) {
        Ok(f) => f,
        Err(_e) => return Ok((ftimes, ads))
    };
    ads = get_ads(filename, &mut info, &mut fs)?;

    let mut attributes = file.attributes();
    while let Some(attribute_item) = attributes.next(&mut info.fs) {
        let attribute_item = attribute_item?;
        let attribute = attribute_item.to_attribute().unwrap();
        match attribute.ty() {
            Ok(NtfsAttributeType::StandardInformation) => continue,
            Ok(NtfsAttributeType::FileName) => {
                fileinfo_filename(&mut info, attribute, &mut ftimes);
                break;
            },
            Ok(NtfsAttributeType::Data) => continue,
            _ => continue,
        }
    }
    Ok((ftimes, ads))
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


fn bytes_to_string(bytes: &Vec<u8>) -> io::Result<String> {
    let s = if bytes.len() >= 256 {
        String::from_utf8_lossy(&bytes[0..255]).into_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };

    let first_bytes_as_string = s.as_str()
                                        .replace('\u{0}', ".")
                                        .to_string();
    Ok(first_bytes_as_string)
}


fn get_ads<T>(arg: &str, info: &mut CommandInfo<T>, fs: &mut BufReader<SectorReader<File>>) -> Result<Vec<DataRun>>
where
    T: Read + Seek,
{
    let file = parse_file_arg(arg, info)?;

    let attributes = file.attributes_raw();
    let mut ads: Vec<DataRun> = Vec::new();
    let mut data: DataRun = DataRun::default();
    let mut buf = [0u8; 4096];

    for attribute in attributes {
        let a = attribute?.clone();
        let ty = a.ty()?;
        if ty == NtfsAttributeType::Data {
            let att = a;
            let _stream = NtfsAttributeValue::from(att.value(fs)?);

            data.name = att.name()?.to_string_lossy();
            data.bytes = att.value_length();
            let bytes_read = att.value(fs)?.read(fs, &mut buf)?;
            data.first_256_bytes = bytes_to_string(&buf[..bytes_read].to_vec())?;
            
            ads.push(data.to_owned());
        }
    }

    Ok(ads)
}