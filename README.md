# fmd
File metadata / forensic tool.  
fmd = File Metadata

```
Author: Brian Kellogg
Pull various file metadata.
See: https://docs.rs/tree_magic/latest/tree_magic/

Usage: fmd <file path> [--pretty | -p]
  Options:
       -p, --pretty     Pretty print JSON
```

Example output:
```
.\fmd.exe --pretty .\fmd.exe
{
  "timestamp": "2022-07-03T17:23:22.345124400+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 846848,
  "mime_type": "application/x-executable",
  "entropy": 6.435221,
  "md5": "05b10d240eab6cb60b789979d6facbc1",
  "sha1": "8556dcc5f205a179bebab19055bd2f3686ff4f57",
  "sha256": "799aadd646cd84f50e49621ef81555914764701759139d8d990d8212fcf66a8f",
  "ssdeep": "12288:bmnsMMBarICYItEvCfIRThdxi3/lTvHDuMY3NKv3KrCwDillR/0:bmsXBarIsEvGMTJi3/lraX3NKvyDil",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "time_compile": "2022-07-03T17:23:18",
    "time_debug": "2022-07-03T17:23:18",
    "linker_major_version": 14,
    "linker_minor_version": 32,
    "imphash": "64bbdb2bb9dca99168c4d17a5cf0e278",
    "imphash_sorted": "4acac28acd517a64e71396eb1c0da9e3",
    "imphash_ssdeep": "24:fDjDpnOwJ3YrXjD5WlKBMdfjEM5L9QTxXXWkKu9/Kbm1stvxCBc+pljpEOovuRZ/:9OdrXZWvt9QTxnW21stv4Bc+pRlGBFK",
    "imphash_ssdeep_sorted": "24:/KW5WkFyFJDCeY9xt1OovbOGMUpnmubu9jveDWDQyl3LLPxQQ8KIKbe07G5u9VJ9:/KW5W6yFhCf9/w3+nmXfhnxQsGvXHlE",
    "imports_lib_count": 2,
    "imports_func_count": 92,
    "imports": [
      {
        "lib": "KERNEL32.dll",
        "count": 91,
        "name": [
          "HeapFree",
          "GetProcessHeap",
          "HeapAlloc",
          "LoadLibraryExW",
          "GetProcAddress",
          "FreeLibrary",
          "HeapReAlloc",
          "GetCommandLineW",
          "SetLastError",
          "GetModuleFileNameW",
          "GetLastError",
          "GetSystemTimeAsFileTime",
          "CloseHandle",
          "SetFilePointerEx",
          "AddVectoredExceptionHandler",
          "SetThreadStackGuarantee",
          "AcquireSRWLockExclusive",
          "ReleaseSRWLockExclusive",
          "Sleep",
          "GetModuleHandleA",
          "TryAcquireSRWLockExclusive",
          "GetStdHandle",
          "GetConsoleMode",
          "WriteConsoleW",
          "GetCurrentDirectoryW",
          "WaitForSingleObjectEx",
          "LoadLibraryA",
          "CreateMutexA",
          "GetCurrentProcess",
          "ReleaseMutex",
          "RtlLookupFunctionEntry",
          "GetModuleHandleW",
          "FormatMessageW",
          "GetFullPathNameW",
          "CreateFileW",
          "GetFileInformationByHandle",
          "DeviceIoControl",
          "ExitProcess",
          "QueryPerformanceCounter",
          "QueryPerformanceFrequency",
          "GetCurrentThread",
          "RtlCaptureContext",
          "AcquireSRWLockShared",
          "GetEnvironmentVariableW",
          "ReleaseSRWLockShared",
          "GetFinalPathNameByHandleW",
          "GetCurrentProcessId",
          "GetCurrentThreadId",
          "InitializeSListHead",
          "RtlVirtualUnwind",
          "IsDebuggerPresent",
          "UnhandledExceptionFilter",
          "SetUnhandledExceptionFilter",
          "GetStartupInfoW",
          "IsProcessorFeaturePresent",
          "RtlUnwindEx",
          "EncodePointer",
          "RaiseException",
          "EnterCriticalSection",
          "LeaveCriticalSection",
          "DeleteCriticalSection",
          "InitializeCriticalSectionAndSpinCount",
          "TlsAlloc",
          "TlsGetValue",
          "TlsSetValue",
          "TlsFree",
          "RtlPcToFileHeader",
          "WriteFile",
          "TerminateProcess",
          "GetModuleHandleExW",
          "GetCommandLineA",
          "FindClose",
          "FindFirstFileExW",
          "FindNextFileW",
          "IsValidCodePage",
          "GetACP",
          "GetOEMCP",
          "GetCPInfo",
          "MultiByteToWideChar",
          "WideCharToMultiByte",
          "GetEnvironmentStringsW",
          "FreeEnvironmentStringsW",
          "SetEnvironmentVariableW",
          "SetStdHandle",
          "GetFileType",
          "GetStringTypeW",
          "CompareStringW",
          "LCMapStringW",
          "HeapSize",
          "FlushFileBuffers",
          "GetConsoleOutputCP"
        ]
      },
      {
        "lib": "bcrypt.dll",
        "count": 1,
        "name": [
          "BCryptGenRandom"
        ]
      }
    ],
    "exports_count": 0,
    "exports": []
  }
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  