<h1 align="center">Nimbus.dll</h1>

<p align="center"><img src="images.steamusercontent.gif" width="300" alt="nimbus"></p>

Nimbus is a userland (ring 3) rootkit for Windows that hides everything carrying its marker. Core NT functions are intercepted with **inline hooks in the ntdll syscall stubs** one prologue patch catches every caller in the process with IAT hooks as fallback and for the Win32-layer APIs.

## Functions

* Hide Processes (`NtQuerySystemInformation` inline hook)
* Hide Files & Directories all directory information classes, head-of-chain records, single-entry enumerations and all-hidden directories (`NtQueryDirectoryFile` / `NtQueryDirectoryFileEx` inline hooks; the filter keeps enumerating instead of reporting empty pages)
* Hide Registry keys & values (`NtEnumerateKey` / `NtEnumerateValueKey` / `NtQueryKey`, hooked in the calling module and in `kernelbase.dll` for the `Reg*` family, with consistent SubKeys/Values counts)
* Hide Services (`EnumServiceGroupW` / `EnumServicesStatusExW`)
* Hide TCP/UDP endpoints of hidden processes (`GetExtendedTcpTable` / `GetExtendedUdpTable` netstat, TCPView, ...)
* **Dynamic configuration** (`HKLM\SOFTWARE\nimbus_config`): `Names` / `Paths` / `Pids` / `Ports` (REG_MULTI_SZ) add hiding rules at runtime extra substrings, full paths (trailing `\` = directory prefix), process ids and TCP/UDP ports. The key is created with a DACL granting Everyone full access, is hidden by the rootkit itself and is re-read live by a background thread
* **Injects into every process** except a small critical-process exclusion list, so any tool an operator picks up sees the filtered view not just a fixed set of targets
* Injection with `NtCreateThreadEx` (falls back to `CreateRemoteThread`); bitness mismatches are skipped instead of crashing the target
* The installer is a **single executable**: `nimbus_installer.exe` embeds `nimbus_src.dll` as an `RCDATA` resource and injects it reflectively from memory; the service re-deploys it at boot if it goes missing
* Runs as a proper Windows service (`-service`): correct SCM status reporting, stop control and auto-start persistence

## How to use

Rename your evil process to `nimbus_xxx.exe` and your evil folders to `nimbus_xxxx`, then run `nimbus_installer.exe` as administrator (it installs the `nimbus` service and starts injecting). Everything whose name contains `nimbus` (case-insensitive) becomes invisible to processes carrying the hook.

## Build

Cross build with mingw-w64:

```sh
./build.sh
```

Outputs in `build/`: `nimbus_installer.exe` (deploy only this file), `nimbus_src.dll` and `test.exe`.

## Test

`test.exe` loads the DLL into itself and verifies every hiding primitive (process list, directory classes, registry counts and enumeration, services, TCP/UDP tables). It requires elevation for the service check:

```
C:\nimbus_test\test.exe C:\nimbus_test\test.log
```

## Notes

* This is a research project for authorized lab environments only.
* Inline hooks intercept every caller in the process, including calls resolved through `GetProcAddress` or delay loads.
