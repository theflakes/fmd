# fmd
File metadata / forensic tool.  
fmd = File Metadata

```
Author: Brian Kellogg
Pull various file metadata.
See: https://docs.rs/tree_magic/latest/tree_magic/

Usage: fmd <file path>
  Options:
       -p, --pretty     Pretty print JSON
```

Example output:
```
fmd.exe -p C:\windows\system32\AcSpecfc.dll
{
  "mime_type": "application/x-executable",
  "fuzzy_hash": "1536:hD6MmkvB6eQmKudOEq7RObnZv9x6sTFLW2f8ZRWupmlkc:4MmkJQmKlvOb9z5LgWupmlkc"
}
```

See:
https://docs.rs/fuzzyhash/latest/fuzzyhash/
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html
https://docs.rs/tree_magic/latest/tree_magic/