# fmd
File metadata / forensic tool.  
fmd = File Metadata

#### Understanding MS PE analysis
http://www.hacktohell.org/2012/04/analysing-pe-files.html  
https://tstillz.medium.com/basic-static-analysis-part-1-9c24497790b6  
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
Usage: fmd [--pretty | -p] ([--strings|-s] #) <file path> [--recurse | -r]
Options:
    -p, --pretty        Pretty print JSON
    -r, --recurse       If passed a directory, recurse into all subdirectories
    -s, --strings #     Look for strings of length # or longer

NOTE: If passed a directory, all files in that directory will be analyzed.
      Harvesting $FILE_NAME timestamps can only be done by running this tool elevated.
      The 'run_as_admin' field shows if the tool was run elevated.

      Harvesting Alternate Data Stream (ADS) information can only be done by running 
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
{
  "runtime_env": {
    "timestamp": "2023-01-11T18:05:10.395464700+00:00",
    "device_type": "Windows 10.0.22621 (Workstation)",
    "run_as_admin": true
  },
  "path": "C:\\Users\\thefl\\Downloads\\RunAsService.exe",
  "directory": "C:\\Users\\thefl\\Downloads",
  "filename": "RunAsService.exe",
  "extension": "exe",
  "bytes": 23552,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "is_link": false,
  "link": {
    "target": "",
    "arguments": "",
    "working_dir": "",
    "icon_location": "",
    "hotkey": "",
    "comment": "",
    "show_command": "",
    "attributes": ""
  },
  "timestamps": {
    "access_fn": "2022-12-24T16:48:24.647",
    "access_si": "2023-01-11T18:05:01.372",
    "create_fn": "2022-12-24T16:48:23.883",
    "create_si": "2022-12-24T16:48:23.883",
    "modify_fn": "2022-12-24T16:48:24.647",
    "modify_si": "2022-12-24T16:50:51.951",
    "mft_record": "2022-12-24T16:48:24.647"
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
      "first_256_bytes": "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://runasservice.com/\r\nHostUrl=http://runasservice.com/Download/RunAsService.exe\r\n"
    }
  ],
  "binary": {
    "is_64": false,
    "is_dotnet": true,
    "is_lib": false,
    "entry_point": "0x6fbe",
    "pe_info": {
      "product_version": "1.0.0.0",
      "original_filename": "1.0.0.0",
      "file_description": "ServiceInstaller",
      "file_version": "1.0.0.0",
      "product_name": "ServiceInstaller",
      "company_name": "Microsoft",
      "internal_name": "RunAsService.exe",
      "legal_copyright": "Copyright © Microsoft 2011"
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
          "entropy": 4.7316236,
          "md5": "5b1cc17d6f1a0bcffda1bc6f451c14a0",
          "ssdeep": "192:Pu/f5epBk4pkW8KUnm9VtD0wsbNL0+zM+LMU4MjnNVWcA/4bsJji+v:PcuNDlF9VtDZsb10+zMKMU4MjnNJc",
          "virt_address": "0x2000",
          "raw_size": 20480,
          "virt_size": 20420
        },
        {
          "name": ".rsrc",
          "entropy": 4.3263397,
          "md5": "8b4b0e26afa8d786659a9cedf2f6db46",
          "ssdeep": "24:eGDR4QymZWBFhZhNmCkWXUcnY3agPN8qPt/dq3ojZ8PAlEbNFjMyiipW3:e4imZWBFhlopa4FPtlq3ojZ8JbNtmMa",
          "virt_address": "0x8000",
          "raw_size": 2048,
          "virt_size": 1888
        },
        {
          "name": ".reloc",
          "entropy": 0.081539415,
          "md5": "e310468da4f5b84f36265d8270c41588",
          "ssdeep": "3:0:",
          "virt_address": "0xa000",
          "raw_size": 512,
          "virt_size": 12
        }
      ]
    },
    "imports": {
      "hashes": {
        "hash": "f34d5f2d4577ed6d9ceec516c1f5a744",
        "hash_sorted": "f34d5f2d4577ed6d9ceec516c1f5a744",
        "ssdeep": "3:rGsLdAIEK:tf",
        "ssdeep_sorted": "3:rGsLdAIEK:tf"
      },
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
```
{
  "runtime_env": {
    "timestamp": "2023-01-11T18:07:33.317621500+00:00",
    "device_type": "Windows 10.0.22621 (Workstation)",
    "run_as_admin": true
  },
  "path": "C:\\Users\\thefl\\Downloads\\RunAsService.exe.lnk",
  "directory": "C:\\Users\\thefl\\Downloads",
  "filename": "RunAsService.exe.lnk",
  "extension": "lnk",
  "bytes": 1206,
  "mime_type": "application/octet-stream",
  "is_hidden": false,
  "is_link": true,
  "link": {
    "target": "C:\\Users\\thefl\\Downloads\\RunAsService.exe",
    "arguments": "--do_evil \"evil stuff\" --make_it_really_evil",
    "working_dir": "C:\\Users\\thefl\\Downloads",
    "icon_location": "%SystemRoot%\\System32\\SHELL32.dll",
    "hotkey": "NO_MODIFIER-NoKeyAssigned",
    "comment": "Definately not evil",
    "show_command": "ShowNormal",
    "attributes": "FILE_ATTRIBUTE_ARCHIVE"
  },
  "timestamps": {
    "access_fn": "2023-01-11T18:05:56.205",
    "access_si": "2023-01-11T18:07:28.681",
    "create_fn": "2023-01-11T18:05:56.190",
    "create_si": "2023-01-11T18:05:56.190",
    "modify_fn": "2023-01-11T18:05:56.190",
    "modify_si": "2023-01-11T18:07:28.057",
    "mft_record": "2023-01-11T18:05:56.205"
  },
  "entropy": 4.6267877,
  "hashes": {
    "md5": "36825bc94d81d08fce309a50a663ddaa",
    "sha1": "aa203ae1e1dd3b76b6b695936f11f8a73cab8413",
    "sha256": "168f41912190771a1f193e2a71670c970c11cc0a9f33ae8ddd376019c49a5ecd",
    "ssdeep": "24:8hbh2NE52qKfe7QATcA7UL4I0sVIFnZfaYYqjjmaN:8T2NE5RCe7TdDIKBU0dN"
  },
  "ads": [
    {
      "name": "",
      "bytes": 1206,
      "first_256_bytes": "L...\u0001\u0014\u0002.....�......F�.\b. ...�\u0004���\u0017�\u0001�)�d�%�\u0001�R��\u0017�\u0001.\\..\u001b...\u0001...............�.:.\u001f.\u00059�\b#\u0003\u0002K�&]�B�\u0011_&.\u0001.&.�\u0011...j��P�\u0010�\u0001�E/��%�\u0001?\u0007{~�%�\u0001\u0014.n.2..\\..�UZ� .RUNASS~1.EXE..R.\t.\u0004.ﾘU\f�+V��....8�....8...............Vk\u0007.R.u.n.A.s.S.e.r.v.i.c.e...e.x.e...\u001c...X...\u001c.."
    }
  ],
  "binary": {
    "is_64": false,
    "is_dotnet": false,
    "is_lib": false,
    "entry_point": "",
    "pe_info": {
      "product_version": "",
      "original_filename": "",
      "file_description": "",
      "file_version": "",
      "product_name": "",
      "company_name": "",
      "internal_name": "",
      "legal_copyright": ""
    },
    "timestamps": {
      "compile": "",
      "debug": ""
    },
    "linker": {
      "major_version": 0,
      "minor_version": 0
    },
    "sections": {
      "total_sections": 0,
      "total_raw_bytes": 0,
      "total_virt_bytes": 0,
      "sections": []
    },
    "imports": {
      "hashes": {
        "hash": "",
        "hash_sorted": "",
        "ssdeep": "",
        "ssdeep_sorted": ""
      },
      "lib_count": 0,
      "func_count": 0,
      "imports": []
    },
    "exports": {
      "count": 0,
      "names": []
    }
  },
  "strings": [
    "RUNASS",
    "1.EXE",
    "C:\\Users\\thefl\\Downloads\\RunAsService.exe",
    "1SPS0"
  ]
}
```
See:  
https://github.com/frank2  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  