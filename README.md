# fmd
File metadata / forensic tool.  
fmd = File Metadata

#### Understanding MS PE analysis
http://www.hacktohell.org/2012/04/analysing-pe-files.html  
https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg  
https://0xrick.github.io/win-internals/pe5/  
  
To compile; install Rust and the MSVC 32 and/or 64 bit environment:
```
x32:        cargo build --release --target i686-pc-windows-msvc
x64:        cargo build --release --target x86_64-pc-windows-msvc
Linux x64:  sudo apt update && sudo apt install mingw-w64
            cargo build --release --target x86_64-pc-windows-gnu
```

```
Author: Brian Kellogg
License: MIT
Purpose: Pull various file metadata.
Usage: fmd [--pretty | -p] ([--strings|-s] #) <file path>
Options:
    -p, --pretty        Pretty print JSON
    -s, --strings #     Look for strings of length # or longer

NOTE: Harvesting $FILE_NAME timestamps can only be acquired by running this tool elevated.
      The 'run_as_admin' field shows if the tool was run elevated.

      Harvesting Alternate Data Stream (ADS) information can only be acquired by running 
      this tool elevated. ADS information is acquired by directly accessing the NTFS which
      requires elevation.

      'runtime_env' stores information on the device that this tool was run on.

      PE Sections:
      - 'total_sections' reports how many PE sections are found after the PE headers.
      - 'total_raw_bytes' cumulative size in bytes of all raw, on disk, sections.
      - 'total_virt_bytes' cumulative size in bytes of all virtual, in memory, sections.
      - if 'total_virt_bytes' is much larger than 'total_raw_bytes', this can indicate
        a packed binary.

      Certain forensic information can only be harvested when the file is analyzed on
      the filesystem of origin. 
      - e.g. timestamps and alternate data streams are lost when the file is moved 
        off of the filesystem of origin.
```

Example output:
```
C:\temp>fmd -p evil.exe
{
  "runtime_env": {
    "timestamp": "2022-12-25T16:29:14.152784800+00:00",
    "device_type": "Windows 10.0.22621 (Workstation)",
    "run_as_admin": true
  },
  "path": "C:\\temp\\evil.exe",
  "bytes": 23552,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "timestamps": {
    "access_fn": "2022-12-25T16:26:41.936",
    "access_si": "2022-12-25T16:26:41.936",
    "create_fn": "2022-12-25T16:26:41.936",
    "create_si": "2022-12-25T16:26:41.936",
    "modify_fn": "2022-12-25T16:26:41.936",
    "modify_si": "2022-12-25T16:26:41.936",
    "mft_record": "2022-12-25T16:26:41.936"
  },
  "entropy": 4.623817,
  "hashes": {
    "md5": "4b92bd03d0c1e1f793ed1b499534211b",
    "sha1": "2574c324fe47119fcd91708451257db00ce4684b",
    "sha256": "09fafb5296afed2324c773acf178552045933995e60c2b81cd66400ccf46a00e",
    "ssdeep": "384:rcuNDlF9VtDZsb10+zMKMU4MjnNJcCWT80T2:rcuZlWb1irMJcUX"
  },
  "ads": [
    {
      "name": "",
      "bytes": 23552,
      "first_256_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$.......PE..L\u0001\u0003.B��Y........�.\u0002\u0001\u000b\u00010..P...\n......�o... ...�....@.. ...\u0002..\u0004.......\u0004........�...\u0002......\u0003.@�..\u0010..\u0010....\u0010..\u0010......\u0010.........."
    },
    {
      "name": "evil",
      "bytes": 34,
      "first_256_bytes": "\"this is hiding info in an ADS\" \r\n"
    },
    {
      "name": "SmartScreen",
      "bytes": 7,
      "first_256_bytes": "Anaheim"
    },
    {
      "name": "Zone.Identifier",
      "bytes": 123,
      "first_256_bytes": "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://evil.com/\r\nHostUrl=http://evil.com/Download/evil.exe\r\n"
    }
  ],
  "binary": {
    "is_64": false,
    "is_dotnet": true,
    "is_lib": false,
    "entry_point": "0x6fbe",
    "pe_info": {
      "product_version": "6.6.6",
      "original_filename": "evil.exe",
      "file_description": "Not evil",
      "file_version": "6.6.6",
      "product_name": "NotEvil",
      "company_name": "UnEvil",
      "internal_name": "notevil",
      "legal_copyright": "@ UnEvil Corp"
    },
    "timestamps": {
      "compile": "2017-10-05T22:25:06",
      "debug": "2017-10-05T22:25:06"
    },
    "linker": {
      "major_version": 48,
      "minor_version": 0
    },
    "sections": {
      "total_sections": 3,
      "total_raw_bytes": 23040,
      "total_virt_bytes": 22320,
      "sections": [
        {
          "name": ".text",
          "virt_address": "0x2000",
          "raw_size": 20480,
          "virt_size": 20420
        },
        {
          "name": ".rsrc",
          "virt_address": "0x8000",
          "raw_size": 2048,
          "virt_size": 1888
        },
        {
          "name": ".reloc",
          "virt_address": "0xa000",
          "raw_size": 512,
          "virt_size": 12
        }
      ]
    },
    "import_hashes": {
      "hash": "f34d5f2d4577ed6d9ceec516c1f5a744",
      "hash_sorted": "f34d5f2d4577ed6d9ceec516c1f5a744",
      "ssdeep": "3:rGsLdAIEK:tf",
      "ssdeep_sorted": "3:rGsLdAIEK:tf"
    },
    "imports": {
      "lib_count": 1,
      "func_count": 1,
      "imports": [
        {
          "lib": "mscoree.dll",
          "count": 1,
          "names": [
            "_CorExeMain"
          ]
        }
      ]
    },
    "exports": {
      "count": 0,
      "names": []
    }
  },
  "strings": []
}
```

See:  
https://github.com/frank2  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  