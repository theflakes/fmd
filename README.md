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
.\fmd.exe --pretty .\fmd.exe
{
  "arch": 64,
  "bytes": 459264,
  "mime_type": "application/x-executable",
  "md5": "1081e7f84087ce43a401b54068c60bad",
  "sha1": "915ee686ee15732c37307a87bdb22473f349d427",
  "sha256": "80cd658abc317a57a99825a93381c24346b09d9dc5dbd6a59b42566db17d3aa0",
  "fuzzy_hash": "6144:ZvLL5xXUa+wsBGLUD3r+iwwe4kHEpHmVO7RiEmQsE8M9C+Y1J/0SD:ZvJ63/BGLq3NkgH+O7RiiCj",
  "imports": [
    {
      "name": "KERNEL32.dll",
      "count": 96
    }
  ]
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  