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
**Chi Squared file analysis**: This calculation counts the number of occurances for each 256 values of a byte in a file. The Chi2 calculation is found in the "chi2" field with the count of each byte possibility [0..256] as a comma seperated string.
- See: https://inria.hal.science/hal-01789936/document

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
  "chi2": "162431,20194,8097,6267,7873,6230,4399,3804,8183,4489,5367,4030,3360,4344,2606,18736,7112,2713,978,1214,1147,2063,9
42,721,2694,851,772,583,887,702,842,1825,10275,1108,604,738,32257,759,605,747,4365,2686,586,886,1070,2737,2829,3793,5743,6060
,1570,905,1097,1169,745,799,3127,2757,1236,912,1177,1771,1738,935,7010,11420,2627,1554,10882,3726,2584,1260,52227,11022,1159,
861,17856,4684,1719,1043,3571,738,1055,1596,2605,1165,2312,1823,1899,524,528,1482,1837,1399,1865,2183,2906,8012,1619,4526,403
8,8610,5861,1685,2686,7896,490,1179,5060,3069,5897,6707,7337,478,6115,5287,11522,4174,1918,1249,3862,1677,787,483,1726,511,74
5,999,3631,1723,1206,9280,11912,4557,699,636,2531,31760,931,17822,3543,12398,385,309,2210,310,427,303,2663,399,234,332,1167,3
28,263,305,966,263,246,283,1547,396,486,415,772,446,481,541,1151,393,415,501,1113,417,518,639,1468,399,351,411,1412,334,1496,
1193,3873,1936,1355,453,1991,530,519,669,6404,4930,1909,2073,1650,781,2026,4353,2241,1881,939,582,444,500,973,725,2495,1388,2
408,704,451,479,602,795,1629,1155,828,829,373,367,472,517,2713,969,1055,535,745,479,489,598,9719,4446,758,3390,1449,1090,547,
619,2790,1618,1094,1022,492,511,1295,1000,3316,2463,2041,1335,1388,1878,2073,21440",
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
          "chi2": "111098,13406,6379,4833,5401,5222,3042,2651,7036,3331,1896,2491,1982,3016,840,18433,6382,2360,684,672,899,1
785,727,513,2273,537,551,407,636,513,421,1447,4785,820,364,507,32009,558,385,441,3931,2437,397,476,584,352,877,472,3203,4981,
374,427,593,367,307,354,2588,2544,457,798,930,512,514,801,4345,10784,1834,1006,10371,3160,1884,940,51823,10207,938,588,17331,
4317,1182,627,2635,611,449,856,1998,774,1718,1423,1582,322,375,878,1267,786,1712,1497,1837,356,262,537,651,483,4040,268,1305,
518,283,391,908,233,430,786,1778,289,969,1050,4600,2628,651,565,1324,494,328,357,1578,337,598,834,3046,1618,1042,9161,11785,4
470,613,532,2271,31658,813,17682,3416,12313,264,206,1955,217,294,226,2455,307,147,216,919,228,196,187,858,176,151,200,1084,15
3,185,171,540,234,173,163,839,159,192,196,844,161,177,342,1217,296,257,315,1281,227,1380,1104,3660,1813,1242,370,1894,451,437
,534,5909,4859,1757,1995,1557,682,1943,4269,2032,1793,865,490,354,414,884,636,2048,1287,2308,622,321,377,487,700,1411,1083,71
3,752,279,289,392,401,2039,885,837,455,610,390,407,502,9494,4306,662,3291,1350,998,433,533,2227,1541,999,930,400,419,1194,922
,3108,2365,1964,1238,1263,1798,1983,20818"
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
          "chi2": "39182,4422,729,645,1134,502,389,353,566,344,2807,1200,1064,1197,279,247,343,234,210,281,186,202,157,170,27
5,172,198,134,195,146,386,343,5324,245,180,187,200,157,169,261,229,213,159,383,437,2355,1900,3259,1843,1039,992,432,447,764,3
91,420,429,177,745,79,176,1227,1190,97,2479,603,395,500,450,522,630,270,278,779,194,243,461,319,504,382,512,89,536,670,543,36
4,551,350,186,163,130,593,539,595,135,641,188,7532,1267,3909,3306,7889,1779,1385,1228,7252,189,760,4004,2772,5357,5816,4623,1
59,4999,4158,6731,1492,1227,658,2339,1115,410,73,72,108,83,92,304,80,85,90,76,59,58,66,107,77,77,94,80,58,94,80,108,65,71,60,
173,69,48,81,102,71,46,89,73,68,63,52,114,92,71,67,67,72,147,232,72,54,73,149,87,78,109,89,106,82,59,69,77,83,77,64,86,104,79
,68,59,62,55,115,103,56,73,58,55,68,64,70,80,71,58,74,57,66,62,68,82,78,67,70,67,75,94,78,107,56,92,57,56,65,62,83,148,64,174
,52,85,64,64,74,111,125,66,86,62,75,93,67,119,58,67,67,52,67,67,64,80,72,49,62,78,66,76,404"
        },
        {
          "name": ".pdata",
          "entropy": 5.793641,
          "md5": "a06ff8b0ed30d0d6073c5938c61c0f06",
          "ssdeep": "192:L8KVwGF9JhD1osV5V60xvIpbWH6Ix0WSFn5C+xX4QXrfjfnceVuf+u:L9VwkFxH80Z8HbB4QX/fnru2",
          "virt_address": "0xdd000",
          "raw_size": 12800,
          "virt_size": 12312,
          "chi2": "3796,125,43,339,284,43,298,235,111,344,239,14,23,11,1035,8,90,27,40,32,37,32,25,17,38,18,13,9,43,16,25,25,
66,27,40,24,40,36,32,27,45,29,28,21,37,22,24,46,71,33,38,34,50,36,35,11,30,20,29,27,34,31,26,31,70,12,43,21,52,18,31,20,44,22
,12,22,38,24,18,23,62,32,25,33,37,19,27,21,61,37,18,8,27,15,15,5,46,18,16,11,22,8,13,20,30,11,8,14,39,14,11,11,56,25,10,18,35
,9,25,13,44,14,23,21,42,31,27,19,89,15,28,21,31,17,15,20,42,12,21,18,32,16,12,12,62,21,16,11,31,15,18,28,49,25,17,23,29,14,19
,24,79,11,30,18,29,11,17,13,34,15,22,10,30,14,17,10,58,14,15,18,44,15,18,16,32,13,21,6,28,15,17,16,60,7,22,17,28,19,10,8,35,1
1,10,10,22,9,13,11,53,10,9,9,44,12,9,8,24,9,11,9,35,10,9,10,48,7,8,9,32,13,11,9,21,12,13,8,26,11,12,14,60,7,17,12,24,15,21,7,
47,19,19,26,39,7,7,16"
        },
        {
          "name": ".xdata",
          "entropy": 5.1570663,
          "md5": "1d433c2abf0c52dbbe6d2d1e7562e7bb",
          "ssdeep": "384:Y7Ae2cV1IND9Sc0APLRtRPWElGj9o0U+:y2qgTZn",
          "virt_address": "0xe1000",
          "raw_size": 18944,
          "virt_size": 18932,
          "chi2": "3558,2198,910,428,1025,443,663,555,393,466,401,312,279,108,70,48,202,91,41,227,15,44,33,21,36,124,6,32,10,
26,2,9,5,14,16,20,2,7,18,17,15,5,2,6,8,8,9,16,540,7,158,6,6,2,9,14,9,15,4,8,4,1,5,5,2,4,345,3,3,5,4,7,4,4,9,7,8,10,4,3,259,3,
25,6,3,4,2,4,2,1,1,2,3,1,2,8,749,4,61,3,1,4,4,1,44,2,4,4,4,2,2,3,649,1,24,4,3,5,1,7,29,3,1,4,3,9,4,4,107,8,46,8,15,10,10,18,3
5,13,16,26,14,9,11,11,5,7,42,6,4,8,19,6,18,3,4,5,4,5,11,7,12,7,76,11,4,7,11,6,7,6,2,6,8,10,5,12,8,7,20,9,5,8,12,8,15,5,10,8,5
,1,7,4,254,8,57,2,10,12,6,5,14,6,2,8,6,8,9,10,219,13,24,3,14,14,9,9,13,7,8,11,1,3,6,21,403,13,34,19,17,12,7,12,5,3,14,5,8,6,7
,5,312,12,11,13,11,8,10,7,9,7,7,8,6,7,6,187"
        },
        {
          "name": ".bss",
          "entropy": 0.0,
          "md5": "d41d8cd98f00b204e9800998ecf8427e",
          "ssdeep": "3::",
          "virt_address": "0xe6000",
          "raw_size": 0,
          "virt_size": 1120,
          "chi2": "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        },
        {
          "name": ".idata",
          "entropy": 4.3447256,
          "md5": "e2a534477d84a4aa71a97a5d2f25f4e3",
          "ssdeep": "96:NwFZ909wFZ90MQx21cqmkQWY8JXXvyP/mfnWBM+AzCkz:WFj0mFj0jx217mkTJJK/mfnWe+AOkz",
          "virt_address": "0xe7000",
          "raw_size": 5120,
          "virt_size": 4648,
          "chi2": "2122,16,25,19,24,19,5,1,5,1,6,0,1,1,363,0,2,0,0,0,4,0,0,0,0,0,4,1,3,1,8,0,3,0,3,0,4,1,0,1,80,2,0,0,3,0,7,0
,8,0,7,6,1,0,2,0,0,1,0,0,33,0,3,1,3,17,8,23,5,20,35,23,17,9,4,1,17,13,11,7,15,3,19,30,22,4,14,25,4,0,2,1,0,1,1,32,5,90,11,64,
50,222,25,10,12,110,6,10,103,46,93,87,153,4,108,52,143,39,13,6,49,51,25,28,29,26,32,50,2,2,5,0,4,1,2,0,2,0,4,2,0,2,4,0,3,0,4,
0,0,0,2,1,3,0,0,1,1,0,2,0,2,0,4,1,3,1,1,0,7,0,2,1,4,0,2,0,0,0,0,0,2,1,9,1,0,0,2,1,3,0,3,0,2,0,0,1,0,0,3,1,2,0,4,0,5,1,5,0,1,0
,0,0,5,1,3,0,1,0,4,0,2,0,3,2,6,0,2,0,0,0,0,1,7,0,3,0,2,0,2,0,2,0,0,0,3,1,2,0,4,0,2,1,2,0,1,1"
        },
        {
          "name": ".CRT",
          "entropy": 0.5435276,
          "md5": "e33e9bf6b29463f68af58eaf2cae587c",
          "ssdeep": "3:TlgqlNs/voqsVk:TlgN/4O",
          "virt_address": "0xe9000",
          "raw_size": 512,
          "virt_size": 120,
          "chi2": "480,7,0,0,0,0,0,2,0,0,3,0,0,0,0,0,2,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,8,0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,1,0,0,0,0,0,0,1,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        },
        {
          "name": ".tls",
          "entropy": 0.0,
          "md5": "bf619eac0cdf3f68d496ea9344137e8b",
          "ssdeep": "3::",
          "virt_address": "0xea000",
          "raw_size": 512,
          "virt_size": 16,
          "chi2": "512,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        },
        {
          "name": ".reloc",
          "entropy": 5.375736,
          "md5": "c59313c669c6dd2a9da789a8fd50dd5c",
          "ssdeep": "96:YWX3DKenhKenGv61cEsZ39CH1VKnoJ3rZ/mW2w0mMntnG/GEcnnzy:Ymee4eI61chCVVKEJmW2VG/GFnzy",
          "virt_address": "0xeb000",
          "raw_size": 5120,
          "virt_size": 4884,
          "chi2": "488,4,0,0,0,0,0,0,72,0,4,12,11,4,1,0,81,0,0,0,1,0,0,0,70,0,0,0,0,0,0,0,82,0,0,0,1,0,0,0,60,0,0,0,1,0,0,0,7
4,0,0,0,0,0,0,0,69,0,0,0,0,0,0,0,78,0,0,0,0,0,0,0,60,0,0,0,0,0,0,0,87,0,0,0,0,0,0,0,63,0,0,0,1,0,0,0,75,0,0,0,0,0,0,0,66,0,0,
0,0,0,0,0,73,0,0,0,0,0,0,0,74,0,0,0,2,0,0,0,80,0,0,0,1,0,0,0,74,0,0,0,1,0,0,0,75,0,0,0,0,0,0,0,76,0,0,0,1,0,0,0,253,133,120,1
46,129,121,131,127,190,157,121,139,140,154,207,186,75,0,0,0,2,0,0,0,78,0,0,0,2,0,0,0,67,0,0,0,0,0,0,0,77,0,0,0,0,0,0,0,85,0,0
,0,0,0,0,0,72,0,0,0,0,0,0,0,66,0,0,0,1,0,0,0,81,0,0,0,1,0,0,0,68,0,0,0,1,0,0,0,68,0,0,0,0,0,0,0"
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