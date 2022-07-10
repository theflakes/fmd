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
  "timestamp": "2022-07-10T17:18:32.011996400+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Users\\thefl\\code\\fmd\\target\\release\\fmd.exe",
  "bytes": 740864,
  "mime_type": "application/x-executable",
  "is_hidden": false,
  "timestamps": {
    "access": "2022-07-10T17:18:31.998",
    "create": "2022-07-04T15:35:43.415",
    "modify": "2022-07-10T17:18:30.435"
  },
  "entropy": 6.41677,
  "md5": "a51e852bec3d0c45dc193141ba0804b8",
  "sha1": "b7c17165935800326559d5b251427664f2f6258d",
  "sha256": "da2504a1202c38dc35af4f600399b1c913fbe7643f74fc4c19bddd5fb47aa408",
  "ssdeep": "12288:5TFRb/gjkqPnuRUTAjjPJKsQTH7+ML3q0OZdLe6w6lRgDP:55RzsiRVfPJKVTH7+E3EdLfw3",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": false,
    "original_filename": "",
    "timestamps": {
      "compile": "2022-07-10T17:18:30",
      "debug": "2022-07-10T17:18:30"
    },
    "linker_major_version": 14,
    "linker_minor_version": 32,
    "imphash": "13fb14c8232d2ac85eb75fab1bf53cc5",
    "imphash_sorted": "4acac28acd517a64e71396eb1c0da9e3",
    "imphash_ssdeep": "24:VjDp3pOwJ3wrXjD5WlKDMdfjEM5L9kTxXXWkKu9/Kbm1stvxCBc+pljpEOovuRZ/:Xc9rXZWtt9kTxnW21stv4Bc+pRlGBFK",
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
          "SetFilePointerEx",
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
  },
  "first_128_bytes": "MZ�.\u0003...\u0004...��..�.......@...................................�...\u000e\u001f�\u000e.�\t�!�\u0001L�!This program cannot be run in DOS mode.\r\r\n$......",
  "strings": []
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  