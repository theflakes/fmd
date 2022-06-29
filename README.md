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
.\fmd.exe --pretty ../../../../../..\Windows\System32\AcSpecfc.dll
{
  "timestamp": "2022-06-29T23:20:42.980696300+00:00",
  "device_type": "Windows 10.0.22000 (Workstation)",
  "path": "C:\\Windows\\System32\\AcSpecfc.dll",
  "bytes": 102400,
  "mime_type": "application/x-executable",
  "md5": "4157e3855a96ecb9055923fc1dbdbfca",
  "sha1": "c9149496528393c89381a5a693b48c5b6205a809",
  "sha256": "d49ecd6dc80af230dde8577ac5d32dea7c7f98a4c9ae7a57178333f2f8f316c4",
  "ssdeep": "1536:hD6MmkvB6eQmKudOEq7RObnZv9x6sTFLW2f8ZRWupmlkc:4MmkJQmKlvOb9z5LgWupmlkc",
  "binary": {
    "is_64": true,
    "is_dotnet": false,
    "is_lib": true,
    "original_filename": "AcSpecfc.dll",
    "imphash": "6d31b225dad22f928cc5acadced3efaf",
    "imphash_sorted": "74f283ff81744eb83835f09d0a0dcbdc",
    "imphash_ssdeep": "48:waKYqcXmnqQ8rAYLRMmtBvTL3fYrBXOZJdeL:VKYbXmnqVfRrtBvTL34B+fA",
    "imphash_ssdeep_sorted": "48:jrbTFMzPt9D1MMtCnHd4XmCXVqqTSEzEdbZqf:3bmLtJ1MsCnHd4XmCXUqTMtY",
    "imports_lib_count": 12,
    "imports_func_count": 112,
    "imports": [
      {
        "lib": "apphelp.dll",
        "count": 6,
        "name": [
          "SE_COM_AddServer",
          "SE_COM_HookObject",
          "SE_COM_Lookup",
          "SE_ShimDPF",
          "SE_GetShimId",
          "SE_COM_AddHook"
        ]
      },
      {
        "lib": "msvcrt.dll",
        "count": 25,
        "name": [
          "memmove",
          "__CxxFrameHandler4",
          "_wcsicmp",
          "_CxxThrowException",
          "_XcptFilter",
          "memcpy",
          "wcsncmp",
          "wcsrchr",
          "_wcsnicmp",
          "_vsnwprintf",
          "__C_specific_handler",
          "wcsspn",
          "iswctype",
          "towlower",
          "wcschr",
          "wcsstr",
          "??1type_info@@UEAA@XZ",
          "?terminate@@YAXXZ",
          "_initterm",
          "malloc",
          "free",
          "_amsg_exit",
          "memset",
          "iswspace",
          "_vscwprintf"
        ]
      },
      {
        "lib": "ntdll.dll",
        "count": 6,
        "name": [
          "RtlAllocateHeap",
          "RtlFreeHeap",
          "NtQueryKey",
          "RtlVirtualUnwind",
          "RtlLookupFunctionEntry",
          "RtlCaptureContext"
        ]
      },
      {
        "lib": "api-ms-win-core-registry-l1-1-0.dll",
        "count": 5,
        "name": [
          "RegOpenKeyExW",
          "RegSetValueExW",
          "RegCloseKey",
          "RegQueryValueExW",
          "RegGetValueW"
        ]
      },
      {
        "lib": "SspiCli.dll",
        "count": 1,
        "name": [
          "GetUserNameExW"
        ]
      },
      {
        "lib": "KERNEL32.dll",
        "count": 49,
        "name": [
          "K32GetProcessImageFileNameW",
          "CreateProcessW",
          "CloseHandle",
          "OpenProcess",
          "K32EnumProcesses",
          "Sleep",
          "CreateThread",
          "GetSystemDirectoryW",
          "SearchPathW",
          "GetExitCodeProcess",
          "ExitProcess",
          "ExpandEnvironmentStringsW",
          "MoveFileW",
          "WaitForSingleObject",
          "GetLastError",
          "SetEnvironmentVariableW",
          "GetTickCount",
          "GetSystemTimeAsFileTime",
          "GetCurrentThreadId",
          "QueryPerformanceCounter",
          "TerminateProcess",
          "SetUnhandledExceptionFilter",
          "UnhandledExceptionFilter",
          "GetCurrentProcess",
          "GetFullPathNameW",
          "GetLongPathNameW",
          "GetWindowsDirectoryW",
          "HeapFree",
          "GetModuleFileNameW",
          "GetFileAttributesW",
          "MultiByteToWideChar",
          "LocalAlloc",
          "GetCurrentProcessId",
          "GetModuleHandleA",
          "LocalFree",
          "GetVersionExW",
          "TlsFree",
          "TlsAlloc",
          "TlsGetValue",
          "TlsSetValue",
          "GetProcessHeap",
          "HeapAlloc",
          "GetModuleHandleExW",
          "FindClose",
          "GetEnvironmentVariableW",
          "GetProcAddress",
          "GetModuleHandleW",
          "GetCommandLineW",
          "FindFirstFileW"
        ]
      },
      {
        "lib": "ADVAPI32.dll",
        "count": 11,
        "name": [
          "QueryServiceStatusEx",
          "StartServiceW",
          "OpenSCManagerW",
          "OpenServiceW",
          "CloseServiceHandle",
          "LsaOpenPolicy",
          "LsaQueryInformationPolicy",
          "LsaFreeMemory",
          "EventWriteTransfer",
          "OpenProcessToken",
          "ControlService"
        ]
      },
      {
        "lib": "ole32.dll",
        "count": 2,
        "name": [
          "CoTaskMemAlloc",
          "CoTaskMemFree"
        ]
      },
      {
        "lib": "SHELL32.dll",
        "count": 2,
        "name": [
          "SHGetSpecialFolderPathW",
          "SHGetFolderPathW"
        ]
      },
      {
        "lib": "USERENV.dll",
        "count": 2,
        "name": [
          "GetUserProfileDirectoryW",
          "GetAllUsersProfileDirectoryW"
        ]
      },
      {
        "lib": "msi.dll",
        "count": 1,
        "name": [
          "ORDINAL 145"
        ]
      },
      {
        "lib": "WINSPOOL.DRV",
        "count": 2,
        "name": [
          "OpenPrinterW",
          "EnumFormsW"
        ]
      }
    ],
    "exports_count": 2,
    "exports": [
      "GetHookAPIs",
      "NotifyShims"
    ]
  }
}
```

See:  
https://docs.rs/fuzzyhash/latest/fuzzyhash/  
https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html  
https://docs.rs/tree_magic/latest/tree_magic/  