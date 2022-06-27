# fmd
File metadata / forensic tool.  
fmd = File Metadata

```
Author: Brian Kellogg
Pull various file metadata.

Usage: fmd <file path>
  Options:
       -p, --pretty     Pretty print JSON
```

Example output:
```
.\fmd.exe --pretty ../../../../../..\Windows\System32\AcSpecfc.dll
{
  "timestamp": "2022-06-27T15:09:42.960582900+00:00",
  "path": "C:\\Windows\\System32\\AcSpecfc.dll",
  "arch": 64,
  "bytes": 102400,
  "mime_type": "application/x-executable",
  "md5": "4157e3855a96ecb9055923fc1dbdbfca",
  "sha1": "c9149496528393c89381a5a693b48c5b6205a809",
  "sha256": "d49ecd6dc80af230dde8577ac5d32dea7c7f98a4c9ae7a57178333f2f8f316c4",
  "fuzzy_hash": "1536:hD6MmkvB6eQmKudOEq7RObnZv9x6sTFLW2f8ZRWupmlkc:4MmkJQmKlvOb9z5LgWupmlkc",
  "imports": [
    {
      "name": "apphelp.dll",
      "count": 6
    },
    {
      "name": "msvcrt.dll",
      "count": 25
    },
    {
      "name": "ntdll.dll",
      "count": 6
    },
    {
      "name": "api-ms-win-core-registry-l1-1-0.dll",
      "count": 5
    },
    {
      "name": "SspiCli.dll",
      "count": 1
    },
    {
      "name": "KERNEL32.dll",
      "count": 49
    },
    {
      "name": "ADVAPI32.dll",
      "count": 11
    },
    {
      "name": "ole32.dll",
      "count": 2
    },
    {
      "name": "SHELL32.dll",
      "count": 2
    },
    {
      "name": "USERENV.dll",
      "count": 2
    },
    {
      "name": "msi.dll",
      "count": 1
    },
    {
      "name": "WINSPOOL.DRV",
      "count": 2
    }
  ]
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  