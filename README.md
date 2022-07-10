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

        NOTE: Harvesting $FILE_NAME timestamps can only be aquired by running this tool elevated.
              The 'is_admin' field shows if the tool was run elevated.
```

Example output:
```
.\fmd.exe --pretty .\fmd.exe
{
  "timestamp": "2022-07-10T23:19:33.442566600+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "is_admin": true,
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 764416,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "timestamps": {
    "access_fn": "2022-07-10T20:56:43.873",
    "access_si": "2022-07-10T23:19:33.537",
    "create_fn": "2022-07-04T15:35:43.415",
    "create_si": "2022-07-04T15:35:43.415",
    "modify_fn": "2022-07-10T20:56:43.873",
    "modify_si": "2022-07-10T23:19:05.797",
    "mft_record": "2022-07-10T20:56:44.010"
  },
  "entropy": 6.405565,
  "md5": "fb462d5f89b1da7118475f96b8c9e74b",
  "sha1": "f53a3251ca05d1f5fb671266a5546b1271084019",
  "sha256": "1dd12e444375c2a58ed2dd9d67cd9d1b1efa3a7cd6d4c9f14a19fe20e3ca0b4e",
  "ssdeep": "12288:X+Ql+KAPzqfy/qsucPfxS6WOja3mcfOK3Sl:OQAPeq/qDcPfxS6Wr3TOGS",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "timestamps": {
      "compile": "2022-07-10T23:19:05",
      "debug": "2022-07-10T23:19:05"
    },
    "linker_major_version": 14,
    "linker_minor_version": 32,
    "imphash": "26c848beee8f7ea16435ac3d90259755",
    "imphash_sorted": "f34e2030c73d6075a29385f7786a62b6",
    "imphash_ssdeep": "48:kvrXZWj1p9QTxnWs1stv4Bc+pRlGBPKhK:YrXZWj1pyTxnWs1stv4Bc+pRmd",
    "imphash_ssdeep_sorted": "48:mb7KW5W6yFhCf9/w3+nmXfhnxQsGvXHlE:UeW5W6YhCf5RnmvhnxQsGvXHlE",
    "imports_lib_count": 3,
    "imports_func_count": 94,
    "imports": [
      {
        "lib": "KERNEL32.dll",
        "count": 91,
        "name": [
          "HeapFree",
          "CloseHandle",
          "SetFilePointerEx",
          "GetLastError",
          "GetCurrentProcess",
          "GetCommandLineW",
          "SetLastError",
          "GetModuleFileNameW",
          "GetSystemTimeAsFileTime",
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
          "FreeLibrary",
          "GetCurrentDirectoryW",
          "WaitForSingleObjectEx",
          "LoadLibraryA",
          "CreateMutexA",
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
          "GetProcAddress",
          "WriteConsoleW",
          "LoadLibraryExW",
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
        "lib": "ADVAPI32.dll",
        "count": 2,
        "name": [
          "OpenProcessToken",
          "GetTokenInformation"
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
  },
  "first_128_bytes": "MZ�.\u0003...\u0004...��..�.......@....................................\u0001..\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$......",
  "strings": []
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  