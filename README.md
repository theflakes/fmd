# fmd
File metadata / forensic tool.  
fmd = File Metadata

#### **Understanding MS PE analysis**
https://practicalsecurityanalytics.com/threat-hunting-with-function-imports/
https://resources.infosecinstitute.com/topic/malware-researchers-handbook/  
http://www.hacktohell.org/2012/04/analysing-pe-files.html  
https://tstillz.medium.com/basic-static-analysis-part-1-9c24497790b6  
https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg  
https://0xrick.github.io/win-internals/pe5/  

**See**:  
https://github.com/frank2  
https://github.com/lilopkins/lnk-rs  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  
  
To compile; install Rust and the MSVC 32 and/or 64 bit environment:
```
x32:        cargo build --release --target i686-pc-windows-msvc
x64:        cargo build --release --target x86_64-pc-windows-msvc
Linux x64:  sudo apt update && sudo apt install mingw-w64
            rustup target add x86_64-pc-windows-gnu
            cargo build --release --target x86_64-pc-windows-gnu
```

# Help and Output
```
Authors: Brian Kellogg
         Jason Langston
License: MIT
Purpose: Pull various file metadata.

Usage: 
    fmd [--pretty | -p] ([--strings|-s] #) <file path> ([--depth | -d] #)
    fmd --pretty --depth 3 --extensions 'exe,dll,pif,ps1,bat,com'
    fmd --pretty --depth 3 --extensions 'not:exe,dll,pif,ps1,bat,com'
        This will process all files that do not have the specified extensions.

Options:
    -d, --depth #       If passed a directory, recurse into all subdirectories
                        to the specified subdirectory depth
    -e, --extensions *  Quoted list of comma seperated extensions
                        - Any extensions not in the list will be ignored
    -i, --int_mtypes    Only analyze files that are more interesting mime types
    -m, --maxsize #     Max file size in bytes to perform content analysis on
                        - Any file larger than this will not have the following run: 
                          hashing, entropy, mime type, strings, PE analysis
    -p, --pretty        Pretty print JSON
    -s, --strings #     Look for strings of length # or longer

If just passed a directory, only the contents of that directory will be processed.
    - i.e. no subdirectories will be processed.

fmd.exe <directory> --depth 1
    - This will work exactly as if the '--depth' 1 option was not specified.

Interesting mime types:
    application/hta
    application/mac-binary
    application/macbinary
    application/octet-stream
    application/x-binary
    application/x-dosexec
    application/x-executable
    application/x-macbinary
    application/x-ms-dos-executable
    application/x-msdownload
    application/x-sharedlib

NOTE: 
    If passed a directory, all files in that directory will be analyzed.
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

### Example output:
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
    "rel_path": "",
    "abs_path": "",
    "arguments": "",
    "working_dir": "",
    "icon_location": "",
    "hotkey": "",
    "comment": "",
    "show_command": "",
    "flags": "",
    "drive_type": "",
    "drive_serial_number": "",
    "volume_label": ""
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
```
{
  "runtime_env": {
    "timestamp": "2023-07-09T01:49:31.335784100+00:00",
    "device_type": "Windows 6.1.7601 (Workstation)",
    "run_as_admin": true
  },
  "path": "Z:\\home\\flakes\\code\\fmd\\target\\x86_64-pc-windows-gnu\\release\\fmd.exe",
  "directory": "Z:\\home\\flakes\\code\\fmd\\target\\x86_64-pc-windows-gnu\\release",
  "filename": "fmd.exe",
  "extension": "exe",
  "bytes": 937472,
  "mime_type": "application/x-ms-dos-executable",
  "is_hidden": false,
  "is_link": false,
  "link": {
    "rel_path": "",
    "abs_path": "",
    "arguments": "",
    "working_dir": "",
    "icon_location": "",
    "hotkey": "",
    "comment": "",
    "show_command": "",
    "flags": "",
    "drive_type": "",
    "drive_serial_number": "",
    "volume_label": ""
  },
  "timestamps": {
    "access_fn": "",
    "access_si": "2023-07-09T01:49:28.692",
    "create_fn": "",
    "create_si": "2023-07-09T01:49:28.712",
    "modify_fn": "",
    "modify_si": "2023-07-09T01:49:28.712",
    "mft_record": ""
  },
  "entropy": 6.3931646,
  "hashes": {
    "md5": "ff04377b4f96a02929413c0730d5519f",
    "sha1": "4877b7e5b8337bd21b35f25458efbcc96d87ae1e",
    "sha256": "0ca3a0ecb9d5bd50ea2a91b6ff74911852ff8f64d3139f1088c341112fde215b",
    "ssdeep": "12288:4kcvW5abSZfkuAfgz3e7wq7ZMjUEDBrLqMJPDgbZZl/jI:4kc+5akAfgzLzDNqAkbR"
  },
  "ads": [],
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "entry_point": "0x14f0",
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
      "compile": "2023-07-09T01:49:28",
      "debug": ""
    },
    "linker": {
      "major_version": 2,
      "minor_version": 38
    },
    "sections": {
      "total_sections": 10,
      "total_raw_bytes": 936448,
      "total_virt_bytes": 934808,
      "sections": [
        {
          "name": ".text",
          "entropy": 6.175901,
          "md5": "2d2dab284ac60a22f26c167fb45532f0",
          "ssdeep": "12288:pkcvW5abSZfkuAfgz3e7wq7ZMjUEDBrLqMJPDgbZZ:pkc+5akAfgzLzDNqAkb",
          "virt_address": "0x1000",
          "raw_size": 698880,
          "virt_size": 698680,
        },
        {
          "name": ".data",
          "entropy": 1.107906,
          "md5": "053fbc14f1d805d6be0f91556e81982b",
          "ssdeep": "3:flBqllmls+tll+l/lXRhoEvhElFJlAElFe/FveKE/3Rt//tfl:ylMs+IhzEMTA11",
          "virt_address": "0xac000",
          "raw_size": 512,
          "virt_size": 288,
          "chi2": "442,12,1,0,0,0,1,7,0,2,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0
,0,1,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,1,0,0,0,1,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12"
        },
        {
          "name": ".rdata",
          "entropy": 5.803681,
          "md5": "01a231ddfe4a802dbef0797e5b64f1b1",
          "ssdeep": "1536:90lTdjRT/7jDp25WMX/LXGsybVfRseqOPZm48LFjlfvOXMwQGK6jv9eys+F6d9pQ:8TDvonX/KsypRm4KGLkt8oC",
          "virt_address": "0xad000",
          "raw_size": 194048,
          "virt_size": 193808,
        },
        {
          "name": ".pdata",
          "entropy": 5.793641,
          "md5": "a06ff8b0ed30d0d6073c5938c61c0f06",
          "ssdeep": "192:L8KVwGF9JhD1osV5V60xvIpbWH6Ix0WSFn5C+xX4QXrfjfnceVuf+u:L9VwkFxH80Z8HbB4QX/fnru2",
          "virt_address": "0xdd000",
          "raw_size": 12800,
          "virt_size": 12312,
        },
        {
          "name": ".xdata",
          "entropy": 5.1570663,
          "md5": "1d433c2abf0c52dbbe6d2d1e7562e7bb",
          "ssdeep": "384:Y7Ae2cV1IND9Sc0APLRtRPWElGj9o0U+:y2qgTZn",
          "virt_address": "0xe1000",
          "raw_size": 18944,
          "virt_size": 18932,
        },
        {
          "name": ".bss",
          "entropy": 0.0,
          "md5": "d41d8cd98f00b204e9800998ecf8427e",
          "ssdeep": "3::",
          "virt_address": "0xe6000",
          "raw_size": 0,
          "virt_size": 1120,
        },
        {
          "name": ".idata",
          "entropy": 4.3447256,
          "md5": "e2a534477d84a4aa71a97a5d2f25f4e3",
          "ssdeep": "96:NwFZ909wFZ90MQx21cqmkQWY8JXXvyP/mfnWBM+AzCkz:WFj0mFj0jx217mkTJJK/mfnWe+AOkz",
          "virt_address": "0xe7000",
          "raw_size": 5120,
          "virt_size": 4648,
        },
        {
          "name": ".CRT",
          "entropy": 0.5435276,
          "md5": "e33e9bf6b29463f68af58eaf2cae587c",
          "ssdeep": "3:TlgqlNs/voqsVk:TlgN/4O",
          "virt_address": "0xe9000",
          "raw_size": 512,
          "virt_size": 120,
        },
        {
          "name": ".tls",
          "entropy": 0.0,
          "md5": "bf619eac0cdf3f68d496ea9344137e8b",
          "ssdeep": "3::",
          "virt_address": "0xea000",
          "raw_size": 512,
          "virt_size": 16,
        },
        {
          "name": ".reloc",
          "entropy": 5.375736,
          "md5": "c59313c669c6dd2a9da789a8fd50dd5c",
          "ssdeep": "96:YWX3DKenhKenGv61cEsZ39CH1VKnoJ3rZ/mW2w0mMntnG/GEcnnzy:Ymee4eI61chCVVKEJmW2VG/GFnzy",
          "virt_address": "0xeb000",
          "raw_size": 5120,
          "virt_size": 4884,
        }
      ]
    },
    "imports": {
      "hashes": {
        "md5": "93bc9d9897e4e465d4287edf79c2eeb8",
        "md5_sorted": "5aa3b1a3a880c918589b831414013445",
        "ssdeep": "48:mbfKW5W6GHMCf9Fa4qcnboxQIOXHcAJG6qJ7k7qtD:UCW5W6GHMCfr5qcnboxQIOXHcAJGhlC4",
        "ssdeep_sorted": "48:mbfdW5W6GHMCf9Fa40cnboxQIOXHcfJG6qJ7k7qtD:U1W5W6GHMCfr50cnboxQIOXHcfJGhlC4"
      },
      "lib_count": 5,
      "func_count": 116,
      "imports": [
        {
          "lib": "ADVAPI32.dll",
          "count": 3,
          "names": [
            {
              "name": "GetTokenInformation",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "OpenProcessToken",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SystemFunction036",
              "more_interesting": false,
              "info": ""
            }
          ]
        },
        {
          "lib": "bcrypt.dll",
          "count": 1,
          "names": [
            {
              "name": "BCryptGenRandom",
              "more_interesting": false,
              "info": ""
            }
          ]
        },
        {
          "lib": "KERNEL32.dll",
          "count": 78,
          "names": [
            {
              "name": "AcquireSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "AcquireSRWLockShared",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "AddVectoredExceptionHandler",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CloseHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CreateFileMappingA",
              "more_interesting": true,
              "info": "Creates or opens a named or unnamed file mapping object for a specified file."
            },
            {
              "name": "CreateFileW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CreateMutexA",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CreateToolhelp32Snapshot",
              "more_interesting": true,
              "info": "Takes a snapshot of the specified processes, heaps,modules, and threads used by the processes."
            },
            {
              "name": "DeleteCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "DuplicateHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "EnterCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ExitProcess",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FindClose",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FindFirstFileW",
              "more_interesting": true,
              "info": "Searches a directory for a file or subdirectory with a name."
            },
            {
              "name": "FindNextFileW",
              "more_interesting": true,
              "info": "Continues a file search for a previous call to the 'findfirstfile/findfirstfileex/findfirstfiletransac
ted' function."
            },
            {
              "name": "FormatMessageW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FreeLibrary",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCommandLineW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetConsoleMode",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentDirectoryW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentProcess",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentThread",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetEnvironmentVariableW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFileInformationByHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFileInformationByHandleEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFinalPathNameByHandleW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFullPathNameW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetLastError",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetModuleFileNameW",
              "more_interesting": true,
              "info": "Retrieves the fully qualified path for the file that contains the specified module."
            },
            {
              "name": "GetModuleHandleA",
              "more_interesting": true,
              "info": "Retrieves a module handle for the specified module."
            },
            {
              "name": "GetModuleHandleW",
              "more_interesting": true,
              "info": "Retrieves a module handle for the specified module."
            },
            {
              "name": "GetProcAddress",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetProcessHeap",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetStartupInfoA",
              "more_interesting": true,
              "info": "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was cr
eated."
            },
            {
              "name": "GetStdHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetSystemTimeAsFileTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapFree",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapReAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "InitOnceBeginInitialize",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "InitOnceComplete",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "InitializeCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LeaveCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LoadLibraryA",
              "more_interesting": true,
              "info": "Loads the specified module into the address space of the calling process."
            },
            {
              "name": "LoadLibraryExW",
              "more_interesting": true,
              "info": "Loads the specified module into the address space of the calling process."
            },
            {
              "name": "MapViewOfFile",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "Module32FirstW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "Module32NextW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "MultiByteToWideChar",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "QueryPerformanceCounter",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "QueryPerformanceFrequency",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RaiseException",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseMutex",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseSRWLockShared",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlCaptureContext",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlLookupFunctionEntry",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlUnwindEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlVirtualUnwind",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetFilePointerEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetLastError",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetThreadStackGuarantee",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetUnhandledExceptionFilter",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "Sleep",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SystemTimeToFileTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SystemTimeToTzSpecificLocalTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TlsAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TlsFree",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TlsGetValue",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TlsSetValue",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TryAcquireSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "UnmapViewOfFile",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "VirtualProtect",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "VirtualQuery",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WaitForSingleObject",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WaitForSingleObjectEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WriteConsoleW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__C_specific_handler",
              "more_interesting": false,
              "info": ""
            }
          ]
        },
        {
          "lib": "msvcrt.dll",
          "count": 31,
          "names": [
            {
              "name": "__getmainargs",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__initenv",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__iob_func",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__lconv_init",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__set_app_type",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "__setusermatherr",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_acmdln",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_amsg_exit",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_cexit",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_commode",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_errno",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_fmode",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_fpreset",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_initterm",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "_onexit",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "abort",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "calloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "exit",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "fprintf",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "free",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "fwrite",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "logf",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "malloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "memcmp",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "memcpy",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "memmove",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "memset",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "signal",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "strlen",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "strncmp",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "vfprintf",
              "more_interesting": false,
              "info": ""
            }
          ]
        },
        {
          "lib": "ntdll.dll",
          "count": 3,
          "names": [
            {
              "name": "NtReadFile",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "NtWriteFile",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlNtStatusToDosError",
              "more_interesting": false,
              "info": ""
            }
          ]
        }
      ]
    },
    "exports": {
      "hashes": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "ssdeep": "3::"
      },
      "count": 0,
      "names": []
    }
  },
  "strings": []
}
```