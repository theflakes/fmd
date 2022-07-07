# fmd
File metadata / forensic tool.  
fmd = File Metadata

```
        Author: Brian Kellogg
        License: MIT
        Purpose: Pull various file metadata.
        Usage: fmd [--pretty | -p] ([--strings|-s] #) <file path>
        Options:
            -p, --pretty        Pretty print JSON
            -s, --strings #     Look for strings of length # or longer
```

Example output:
```
.\fmd.exe --pretty .\fmd.exe
{
  "timestamp": "2022-07-05T21:18:00.207689500+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 739840,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "timestamps": {
    "access": "2022-07-05T21:18:00.196",
    "create": "2022-07-04T15:35:43.415",
    "modify": "2022-07-05T21:17:56.728"
  },
  "entropy": 6.4159017,
  "md5": "9f4743bf72cacd02991356b441d9c186",
  "sha1": "7728dce9af5567facb98ebe63e52f34e4c0255e0",
  "sha256": "7b0de7e2e16bc90dabdb127652430fca48105f41208f2c1629edc942e1878e3b",
  "ssdeep": "12288:TDU7uYoHrzX/5d6qOvLAbJmTL43I9ivVg14lR8t:TDY8H/Xxd6qcLAbJm43JV+Nt",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "timestamps": {
      "compile": "2022-07-05T21:17:56",
      "debug": "2022-07-05T21:17:56"
    },
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
    "first_128_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$......"
  },
  "strings": []
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  