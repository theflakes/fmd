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
            cargo build --release --target x86_64-pc-windows-gnu
```
*Chi Squared file analysis*: This calculation counts the number of occurances for each 256 values of a byte in a file. The Chi2 calculation is found in the "chi2" field with the count of each byte possibility [0..256] as a comma seperated string.
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
    "application/hta",
    "application/mac-binary",
    "application/macbinary",
    "application/octet-stream",
    "application/x-binary",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-macbinary",
    "application/x-ms-dos-executable",
    "application/x-msdownload",
    "application/x-sharedlib"

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
  "chi2": "162534,20199,8096,6266,7873,6231,4406,3788,8177,4470,5355,4030,3376,4330,2625,18725,7096,2718,964,1219,1170,2056,9
  36,723,2704,858,754,559,902,696,854,1819,10280,1136,575,757,32420,765,604,742,4360,2668,550,870,1090,2737,2847,3780,5733,6040
  ,1561,907,1096,1163,762,813,3141,2749,1218,908,1162,1764,1736,943,7003,11472,2620,1543,10901,3692,2571,1271,52050,11175,1182,
  854,17830,4654,1750,1058,3546,745,1076,1573,2600,1189,2302,1836,1883,537,533,1502,1858,1355,1873,2190,2895,8021,1639,4511,405
  2,8609,5854,1702,2655,7893,496,1196,5046,3087,5904,6702,7358,472,6135,5275,11562,4104,1903,1249,3846,1671,787,478,1756,462,75
  0,997,3484,1739,1205,9279,11886,4570,691,621,2511,31753,919,17782,3547,12386,384,308,2271,290,441,286,2660,432,273,310,1180,3
  14,267,293,978,249,248,281,1494,416,491,414,773,450,451,534,1179,419,403,511,1118,443,494,645,1474,395,346,421,1406,371,1491,
  1195,3861,1913,1342,461,1988,535,517,701,6411,4920,1891,2090,1646,788,2010,4372,2244,1886,942,575,492,501,961,727,2498,1381,2
  408,710,444,459,612,787,1634,1158,864,848,356,365,459,535,2658,945,1083,542,728,470,505,617,9696,4429,743,3388,1448,1090,545,
  630,2823,1638,1092,1038,483,509,1285,1002,3321,2456,2063,1351,1374,1863,2081,21435",
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
Identify more interesting imports:
```
./fmd -p ./fmd.exe
{
  "runtime_env": {
    "timestamp": "2023-05-08T14:14:01.160860300+00:00",
    "device_type": "Windows 10.0.22621 (Workstation)",
    "run_as_admin": true
  },
  "path": "D:\\code\\fmd\\target\\release\\fmd.exe",
  "directory": "D:\\code\\fmd\\target\\release",
  "filename": "fmd.exe",
  "extension": "exe",
  "bytes": 912384,
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
    "access_fn": "2023-05-08T14:06:07.327",
    "access_si": "2023-05-08T14:14:00.858",
    "create_fn": "2023-05-08T14:06:07.293",
    "create_si": "2023-05-08T14:06:07.293",
    "modify_fn": "2023-05-08T14:06:07.327",
    "modify_si": "2023-05-08T14:06:07.327",
    "mft_record": "2023-05-08T14:06:07.511"
  },
  "entropy": 6.3614507,
  "hashes": {
    "md5": "f771e9ca94e03156d156e59cf1108acf",
    "sha1": "b2e11e6a56d6195959a48dbc59503e82ae656f5c",
    "sha256": "e2862b30b4629f48068edd292fd100e8ff2d9c0f5b621cdd5dd994f48de38205",
    "ssdeep": "12288:iTUxmsNjTtfnRRIAk/HsnDvj5eqpb8qhLx7VcptoZ:iTUTtfDIX/Hs35xpbrX7Gpti"
  },
  "ads": [
    {
      "name": "",
      "bytes": 912384,
      "first_256_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$.......�O8��.V��.V��.V�0\\U��.V�0\\S�j.V�0\\R��.V�\\RS��.V�\\RR��.V�\\RU��.V�0\\W��.V��.W��.V��.V��.V�:ST��.V�Rich�.V�................PE..d�\u0006"
    }
  ],
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "entry_point": "0x8783c",
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
      "compile": "2023-05-08T14:06:07",
      "debug": "2023-05-08T14:06:07"
    },
    "linker": {
      "major_version": 14,
      "minor_version": 35
    },
    "sections": {
      "total_sections": 6,
      "total_raw_bytes": 911360,
      "total_virt_bytes": 914640,
      "sections": [
        {
          "name": ".text",
          "entropy": 6.2606473,
          "md5": "b27fda7b8dda8b67b4a83f0397eb6e2e",
          "ssdeep": "12288:hTUxmsNjTtfnRRIAk/HsnDvj5eqpb8qhLx7Vcpt:hTUTtfDIX/Hs35xpbrX7Gpt",
          "virt_address": "0x1000",
          "raw_size": 629760,
          "virt_size": 629584
        },
        {
          "name": ".rdata",
          "entropy": 5.620502,
          "md5": "3514e91c3409ea2169e3318bcd4643f0",
          "ssdeep": "3072:P06t6vb0qRsiVcZpkZvwNQmuILUS5AKQdlLkt8n1OC13L01vlftQj0UV:JkSIMYS5wWev55",
          "virt_address": "0x9b000",
          "raw_size": 254976,
          "virt_size": 254480
        },
        {
          "name": ".data",
          "entropy": 2.077,
          "md5": "02a216035bd81096ad2a6d35058abfbd",
          "ssdeep": "24:bY1Bf6uSkeKP6uSkeK8hBSqRSSSS1wVVbeC1u:b8BTk4TkPkCSSSSyHbeC1u",
          "virt_address": "0xda000",
          "raw_size": 3072,
          "virt_size": 8024
        },
        {
          "name": ".pdata",
          "entropy": 5.765786,
          "md5": "3e910837566d751a4ca1b304f2b7b64b",
          "ssdeep": "384:k/+PYyFpNJDRvZT32NWIybFBS18BA9v3BfpiUJ6UrMDiFpM16c5jR/BX:kilHDT7IyzS1WWmUrMDTv",
          "virt_address": "0xdc000",
          "raw_size": 16384,
          "virt_size": 16008
        },
        {
          "name": "_RDATA",
          "entropy": 3.3046613,
          "md5": "31ff6f2798d8f7c00aaf516b84718be2",
          "ssdeep": "6:P/hxYw51Uoit95idqOJMYwCTA4Fbb3zyveNA4XK13H:If6PCYo4FbKH",
          "virt_address": "0xe0000",
          "raw_size": 512,
          "virt_size": 348
        },
        {
          "name": ".reloc",
          "entropy": 5.3366485,
          "md5": "e37675ee4c4f5dcb7b3fb0f74698cfac",
          "ssdeep": "192:8Qn81cD1c+hvJe725jRmVJPISajeJzT/X+uYAiz+sssEXL:8Qn8KBBe72tRmTAazjzsssE",
          "virt_address": "0xe1000",
          "raw_size": 6656,
          "virt_size": 6196
        }
      ]
    },
    "imports": {
      "hashes": {
        "md5": "ad3f2eabfdf67bac7ed8a69a4c402917",
        "md5_sorted": "5919e44bd5534590d79649bcc72515fc",
        "ssdeep": "48:pErXcdf/p9zWwTxrWA1stv4Bc+pRl7EcbfK:arXcV/pJWwTxrWA1stv4Bc+pRrS",
        "ssdeep_sorted": "48:mbfKW5W6yFQCg9/w3+nmPc1hnxQsGvXHcvB:UCW5W6YQCg5Rnm8hnxQsGvXHcvB"
      },
      "lib_count": 3,
      "func_count": 105,
      "imports": [
        {
          "lib": "KERNEL32.dll",
          "count": 101,
          "names": [
            {
              "name": "CloseHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentProcess",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetFilePointerEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetLastError",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FindFirstFileW",
              "more_interesting": true,
              "info": "Searches a directory for a file or subdirectory with a name."
            },
            {
              "name": "FindClose",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCommandLineW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetLastError",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetModuleFileNameW",
              "more_interesting": true,
              "info": "Retrieves the fully qualified path for the file that contains the specified module."
            },
            {
              "name": "AddVectoredExceptionHandler",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetThreadStackGuarantee",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentThread",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapReAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FileTimeToSystemTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SystemTimeToTzSpecificLocalTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SystemTimeToFileTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetTimeZoneInformation",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetProcessHeap",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "Sleep",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetModuleHandleA",
              "more_interesting": true,
              "info": "Retrieves a module handle for the specified module."
            },
            {
              "name": "TryAcquireSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetStdHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetConsoleMode",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FreeLibrary",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "MultiByteToWideChar",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WriteConsoleW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentDirectoryW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WaitForSingleObjectEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LoadLibraryA",
              "more_interesting": true,
              "info": "Loads the specified module into the address space of the calling process."
            },
            {
              "name": "CreateMutexA",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseMutex",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlLookupFunctionEntry",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetModuleHandleW",
              "more_interesting": true,
              "info": "Retrieves a module handle for the specified module."
            },
            {
              "name": "FormatMessageW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CreateFileW",
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
              "name": "GetFullPathNameW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FindNextFileW",
              "more_interesting": true,
              "info": "Continues a file search for a previous call to the 'findfirstfile/findfirstfileex/findfirstfiletransacted' function."
            },
            {
              "name": "AcquireSRWLockExclusive",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ExitProcess",
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
              "name": "GetSystemTimeAsFileTime",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlCaptureContext",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "AcquireSRWLockShared",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "ReleaseSRWLockShared",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetEnvironmentVariableW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFinalPathNameByHandleW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetProcAddress",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LoadLibraryExW",
              "more_interesting": true,
              "info": "Loads the specified module into the address space of the calling process."
            },
            {
              "name": "WaitForSingleObject",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapFree",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentProcessId",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCurrentThreadId",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "InitializeSListHead",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlVirtualUnwind",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "IsDebuggerPresent",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "UnhandledExceptionFilter",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetUnhandledExceptionFilter",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetStartupInfoW",
              "more_interesting": true,
              "info": "Retrieves the contents of the STARTUPINFO structure that was specified when the calling process was created."
            },
            {
              "name": "IsProcessorFeaturePresent",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlUnwindEx",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "EncodePointer",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RaiseException",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "EnterCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LeaveCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "DeleteCriticalSection",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "InitializeCriticalSectionAndSpinCount",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TlsAlloc",
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
              "name": "TlsFree",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "RtlPcToFileHeader",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WriteFile",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "TerminateProcess",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetModuleHandleExW",
              "more_interesting": true,
              "info": "Retrieves a module handle for the specified module and increments the module's reference count."
            },
            {
              "name": "GetCommandLineA",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FindFirstFileExW",
              "more_interesting": true,
              "info": "Searches a directory for a file or subdirectory with a name."
            },
            {
              "name": "IsValidCodePage",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetACP",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetOEMCP",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetCPInfo",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "WideCharToMultiByte",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetEnvironmentStringsW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FreeEnvironmentStringsW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetEnvironmentVariableW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "SetStdHandle",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetFileType",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetStringTypeW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FlsAlloc",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FlsGetValue",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FlsSetValue",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FlsFree",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "CompareStringW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "LCMapStringW",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "HeapSize",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "FlushFileBuffers",
              "more_interesting": false,
              "info": ""
            },
            {
              "name": "GetConsoleOutputCP",
              "more_interesting": false,
              "info": ""
            }
          ]
        },
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