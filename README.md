# fmd
File metadata / forensic tool.  
fmd = File Metadata


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
              The 'run_as_admin' field shows if the tool was run elevated. If the MFT can be accessed,
              its $STANDARD_INFORMATION dates are preferred.
```

Example output:
```
C:\temp>fmd -p RunAsService.exe
{
  "timestamp": "2022-12-13T02:49:09.718219500+00:00",
  "device_type": "Windows 10.0.19045 (Workstation)",
  "run_as_admin": true,
  "path": "C:\\temp\\RunAsService.exe",
  "bytes": 23552,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "timestamps": {
    "access_fn": "2022-11-19T16:00:21.900",
    "access_si": "2022-11-19T16:00:21.900",
    "create_fn": "2022-11-19T16:00:21.900",
    "create_si": "2022-11-19T16:00:21.900",
    "modify_fn": "2022-11-19T16:00:21.900",
    "modify_si": "2022-11-19T16:00:21.900",
    "mft_record": "2022-11-19T16:00:21.900"
  },
  "entropy": 4.623817,
  "md5": "4b92bd03d0c1e1f793ed1b499534211b",
  "sha1": "2574c324fe47119fcd91708451257db00ce4684b",
  "sha256": "09fafb5296afed2324c773acf178552045933995e60c2b81cd66400ccf46a00e",
  "ssdeep": "384:rcuNDlF9VtDZsb10+zMKMU4MjnNJcCWT80T2:rcuZlWb1irMJcUX",
  "ads": [
    {
      "name": "",
      "bytes": 23552,
      "first_256_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$.......PE..L\u0001\u0003.B��Y........�.\u0002\u0001\u000b\u00010..P...\n......�o... ...�....@.. ...\u0002..\u0004.......\u0004........�...\u0002......\u0003.@�..\u0010..\u0010....\u0010..\u0010......\u0010.........."
    },
    {
      "name": "evil",
      "bytes": 17,
      "first_256_bytes": "\"this is evil\" \r\n"
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
    "pe_info": {
      "product_version": "10.0.22621.674",
      "original_filename": "RunAsService.exe",
      "file_description": "RunAsService.exe",
      "file_version": "10.0.22621.674 (WinBuild.160101.0800)",
      "product_name": "RunAsService",
      "company_name": "Evil Corp",
      "internal_name": "RunAsService.exe",
      "legal_copyright": "I will pwn your stuff!!!"
    },
    "timestamps": {
      "compile": "2017-10-05T22:25:06",
      "debug": "2017-10-05T22:25:06"
    },
    "linker_major_version": 48,
    "linker_minor_version": 0,
    "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "imphash_sorted": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "imphash_ssdeep": "3:rGsLdAIEK:tf",
    "imphash_ssdeep_sorted": "3:rGsLdAIEK:tf",
    "imports_lib_count": 1,
    "imports_func_count": 1,
    "imports": [
      {
        "lib": "mscoree.dll",
        "count": 1,
        "name": [
          "_CorExeMain"
        ]
      }
    ],
    "exports_count": 0,
    "exports": []
  },
  "strings": []
}
```

See:  
https://github.com/frank2  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  