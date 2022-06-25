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
.\fmd.exe --pretty .\fmd.exe
{
  "bytes": 453120,
  "mime_type": "application/x-executable",
  "md5": "7b85c1b2a0e6aa641e9c0657256efaf4",
  "sha1": "81f909b63ae250eda2038a1e9ee30a1db6a277da",
  "sha256": "6735d16bb91fef82abf9cbfb6d45d7babde042cc66757fefae10c5614b57c348",
  "fuzzy_hash": "6144:f8rgbmFAgpy+wY4lFhXxkI3xNGAdRlH29xnQx0/U9h36fD9+nntfQ50ox:6JfX4lFhhkodRixnQKU9e9Kox"
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  