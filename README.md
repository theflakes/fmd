# fmd
File metadata / forensic tool.  
fmd = File Metadata

#### Understanding MS PE analysis
https://resources.infosecinstitute.com/topic/malware-researchers-handbook/  
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
        "md5": "f34d5f2d4577ed6d9ceec516c1f5a744",
        "md5_sorted": "f34d5f2d4577ed6d9ceec516c1f5a744",
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
    "timestamp": "2023-01-12T00:28:57.871971300+00:00",
    "device_type": "Windows 10.0.22621 (Workstation)",
    "run_as_admin": true
  },
  "path": "C:\\Users\\thefl\\Downloads\\SharpHound.exe.lnk",
  "directory": "C:\\Users\\thefl\\Downloads",
  "filename": "SharpHound.exe.lnk",
  "extension": "lnk",
  "bytes": 1446,
  "mime_type": "application/octet-stream",
  "is_hidden": false,
  "is_link": true,
  "link": {
    "rel_path": "",
    "abs_path": "E:\\shared\\SharpHound.exe",
    "arguments": "-blah \"hi there\"",
    "working_dir": "E:\\shared",
    "icon_location": "E:\\shared\\SharpHound.exe",
    "hotkey": "NO_MODIFIER-NoKeyAssigned",
    "comment": "not evil, please just run me",
    "show_command": "ShowNormal",
    "flags": "HAS_LINK_TARGET_ID_LIST | HAS_LINK_INFO | HAS_WORKING_DIR | HAS_ARGUMENTS | HAS_ICON_LOCATION | IS_UNICODE | ENABLE_TARGET_METADATA",
    "drive_type": "DriveFixed",
    "drive_serial_number": "1963598570",
    "volume_label": "\"Bkps\""
  },
  "timestamps": {
    "access_fn": "2023-01-11T15:23:46.799",
    "access_si": "2023-01-12T00:26:43.962",
    "create_fn": "2023-01-11T15:23:46.790",
    "create_si": "2023-01-11T15:23:46.790",
    "modify_fn": "2023-01-11T15:23:46.793",
    "modify_si": "2023-01-11T16:25:01.945",
    "mft_record": "2023-01-11T15:23:46.801"
  },
  "entropy": 4.3651047,
  "hashes": {
    "md5": "fc751be8019b136611299843b174da3f",
    "sha1": "301ef23cfbba2e105ad1fb7e23290c72d9720d4d",
    "sha256": "58dd16a28e5b7edee3ee2ed5a2159135ef53b70ca31f6a2fdf3513cdf10068cc",
    "ssdeep": "24:8GC8aWsnLnN5/yLkZmdyDkNQ1DHdz4/LFtVMwLs2cXpoHs/dmn7:8G/SnLeyDH1DgGpGIc"
  },
  "ads": [
    {
      "name": "",
      "bytes": 1446,
      "first_256_bytes": "L...\u0001\u0014\u0002.....�......F�.\b. ...�Y\u001a�,\u0016�\u0001fr\u001f��%�\u0001.��~v��\u0001.\f\u0010.....\u0001...............�.\u0014.\u001fP�O� �:i\u0010��\b.+00�\u0019./E:\\...................T.1.....)VE\r0.shared..>.\t.\u0004.ﾖU�\u0014+V�z....�.....\u0004...............'�\u0012\u0001s.h.a.r.e.d...\u0016.j.2..\f\u0010.\u0003U�� .SHARPH~1.EXE..N.\t.\u0004.ﾖU\\�+V�z...."
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
        "md5": "",
        "md5_sorted": "",
        "ssdeep": "",
        "ssdeep_sorted": ""
      },
      "lib_count": 0,
      "func_count": 0,
      "imports": []
    },
    "exports": {
      "hashes": {
        "md5": "",
        "ssdeep": ""
      },
      "count": 0,
      "names": []
    }
  },
  "strings": []
}
```
See:  
https://github.com/frank2  
https://github.com/lilopkins/lnk-rs  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  