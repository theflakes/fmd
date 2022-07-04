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
  "timestamp": "2022-07-04T20:15:22.450972400+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 734720,
  "mime_type": "application/x-executable",
  "entropy": 6.417216,
  "md5": "9e89c5e92195de9dc30909c60a1bbea2",
  "sha1": "203f1bdc4aa819fd17dd5de0e8b164b1f977d52e",
  "sha256": "91eaf2e4dc114b45c4deadeb4fe9de486f737482fd8d872dbce0be9fd4e7b9b2",
  "ssdeep": "12288:LF8L6vXa799nT+LPRiGm3hJp4xHUJbyrYlR:SLMKJ9nqLPRib3hJwU9y",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "time_compile": "2022-07-04T20:13:44",
    "time_debug": "2022-07-04T20:13:44",
    "linker_major_version": 14,
    "linker_minor_version": 32,
    "imphash": "cc86782ee04d5c8f4491f3ee99b6c550",
    "imphash_sorted": "4acac28acd517a64e71396eb1c0da9e3",
    "imphash_ssdeep": "24:VjDp3pOwJ3YrXjD5WlKDMdfjEM5L9QTxXXWkKu9/Kbm1stvxCBc+pljpEOovuRZ/:XcdrXZWtt9QTxnW21stv4Bc+pRlGBFK",
    "imphash_ssdeep_sorted": "24:/KW5WkFyFJDCeY9xt1OovbOGMUpnmubu9jveDWDQyl3LLPxQQ8KIKbe07G5u9VJ9:/KW5W6yFhCf9/w3+nmXfhnxQsGvXHlE",
    "imports_lib_count": 2,
    "imports_func_count": 92,
    "imports": [
      {
        "lib": "KERNEL32.dll",
        "count": 91,
        "name": [
          "LoadLibraryExW",
          "GetProcAddress",
          "FreeLibrary",
          "HeapFree",
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
          "HeapAlloc",
          "GetProcessHeap",
          "HeapReAlloc",
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
    "exports": [],
    "first_128_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$......",
    "strings": []
  }
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  