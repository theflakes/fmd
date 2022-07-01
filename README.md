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
PS C:\Users\thefl\code\fmd\target\release> .\fmd.exe --pretty .\fmd.exe
{
  "timestamp": "2022-07-01T17:36:26.575236900+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 709120,
  "mime_type": "application/x-executable",
  "entropy": 6.4169397,
  "md5": "1877a21e448649f0a094a5923bd31cdc",
  "sha1": "ec8ad5dbd295ceb9cabfd3698c2e263809548cab",
  "sha256": "1e59809bf790c8b24833394c232ec30bf4aacd5fabc551c1236ddcc9a929b4c6",
  "ssdeep": "12288:skLPeOsiNbjJaZ7bSyw3avJEIH+mJ34MSklRqjL:sjON1EZ7bS/3avRJa",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "imphash": "9cbb8c39ec62bc556d61008a2e2fc75a",
    "imphash_sorted": "a9cdc34687d6e7a32a62b4fcaff60851",
    "imphash_ssdeep": "48:XcdrXZWGcYt93fCTxnW51stv48pRKGBeK:XcrXZWGcYt5fCTxnW51stv48pRb",
    "imphash_ssdeep_sorted": "48:/KW5W6yFhCf9/w3+nmXfphnxQEGvXH8jE:iW5W6YhCf5RnmvphnxQEGvXH8jE",
    "imports_lib_count": 2,
    "imports_func_count": 94,
    "imports": [
      {
        "lib": "KERNEL32.dll",
        "count": 93,
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
          "ReadFile",
          "AddVectoredExceptionHandler",
          "SetThreadStackGuarantee",
          "AcquireSRWLockExclusive",
          "ReleaseSRWLockExclusive",
          "HeapReAlloc",
          "HeapAlloc",
          "GetProcessHeap",
          "Sleep",
          "GetModuleHandleA",
          "TryEnterCriticalSection",
          "LeaveCriticalSection",
          "GetStdHandle",
          "GetConsoleMode",
          "WriteFile",
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
          "InitializeCriticalSection",
          "EnterCriticalSection",
          "ExitProcess",
          "QueryPerformanceCounter",
          "QueryPerformanceFrequency",
          "GetCurrentThread",
          "RtlCaptureContext",
          "AcquireSRWLockShared",
          "GetEnvironmentVariableW",
          "ReleaseSRWLockShared",
          "GetFinalPathNameByHandleW",
          "GetConsoleOutputCP",
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
          "DeleteCriticalSection",
          "InitializeCriticalSectionAndSpinCount",
          "TlsAlloc",
          "TlsGetValue",
          "TlsSetValue",
          "TlsFree",
          "RtlPcToFileHeader",
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
          "FlushFileBuffers"
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