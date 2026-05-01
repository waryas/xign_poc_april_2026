

## Protocol refresher

Device is accessed by `CreateFileW(L"\\\\.\\xhunter1", ...)`. Commands are sent with `WriteFile`, not `DeviceIoControl`. Dispatch is **not** via `IRP_MJ_DEVICE_CONTROL`; the driver only registers `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_WRITE`.

```
IRP_MJ_WRITE buffer, 624 bytes, DO_BUFFERED_IO:
  +0  DWORD  in_size = 624
  +4  DWORD  magic   = 0x345821AB    (verified empirically from cmp at sub_14000B568;
                                      IDA decompile printed the constant as decimal
                                      878191019 which I initially mis-hexed)
  +8  DWORD  nonce   (echoed as ~nonce in rsp[+8])
 +12  DWORD  command (∈ { 774..821 }, not contiguous)
 +16  QWORD  response VA (user VA in caller; mapped via UserMode MDL, 762-byte write)
 +24  ...    per-command args

Response:
  +0  DWORD  size = 624
  +4  DWORD  magic = 0x12121212
  +8  DWORD  ~nonce
 +12  DWORD  NTSTATUS (negative = driver failure)
 +16  ...    per-command result fields (up to 762 bytes total)
```

Auth is per-command via `sub_140005E84()` — returns true iff `(driver_flag_table[caller_PID] & 0x80000008) == 0x80000008`. Bits get stamped by the process-image-load notify callback that parses a trust cache shipped with the driver (`sub_140007074`), not by any IOCTL.

---

## Per-command table

Legend for the last column:
- **R** = arbitrary or near-arbitrary **read** primitive reachable through this command
- **W** = arbitrary **write** primitive
- **X** = arbitrary code **execution** primitive
- **L** = information **leak** / narrower disclosure
- **A** = auth bypass / privilege confusion
- **OOB** = out-of-bounds pool read
- `auth` = requires `sub_140005E84()` (trusted-process flag)
- `—` = no security-relevant primitive identified

| Cmd | Handler (`sub_`) | Purpose (inferred) | Key sinks | Class |
|-----|-----|-----|-----|-----|
| 774 | `140001F54` | Ping/echo | — | — |
| 775 | `140001DD8` | Set per-PID flag bits (low word) | `sub_140005F98(pid=cmd+24, flags=cmd+28)` | **A — AUTH GATE BYPASS.** Caller chooses both target PID and low-16 flag bits. Setting bit 3 (`0x8`) on self is step 2 of the 2-IOCTL unauth auth-bypass chain. See Auth section. |
| 776 | `140003598` | Clear per-PID flags | `sub_140006324(pid=cmd+24)` | **A** (same class as 775) |
| 777 | `140003498` | Register caller PID, set upper-16 flag bits to `0x8000` | `sub_140006A10`+`sub_140006418(self, 0x80000000)` | **A** — sets bit 31 on self. **Step 1 of the 2-IOCTL unauth auth-bypass chain** (pair with cmd 775 for bit 3). Does not yield auth alone, but trivially does with cmd 775. |
| 778 | `140003708` | Unregister caller | `sub_140006AC4`+`sub_140006190` | — |
| 779 | `140003398` | Enumerate trusted PIDs to user buffer; size-checked | `sub_140006968` under UserMode MDL | **L** (discloses which PIDs are currently "trusted") |
| 782 | `1400035D4` | Set a global byte flag | `sub_14000739C(cmd+24 byte)` | — |
| 783 | `1400026C8` | Version/status query | `sub_140007394()` | — |
| 785 | `1400030B8` | **Open any process by PID with user-specified access mask** | `sub_1400087F4` → `ObOpenObjectByPointer(KernelMode, user access mask)` | **A**, **W-capable** (the returned user-mode handle has arbitrary access, including `PROCESS_VM_WRITE` + `PROCESS_CREATE_THREAD`, skipping DACL) — `auth` |
| 786 | `1400022F8` | Counter query | `sub_140004B34()` | — |
| 787 | `140003278` | Cross-process user-space **read** (handle access-mask bypass) | `sub_140007874` ladder → `sub_140008924` (per-byte, `srcVA < MmSystemRangeStart`) | **A**, **R** (user-space of any non-protected process) |
| 788 | `1400031C4` | **Arbitrary kernel read** | `sub_1400084AC` per-byte copy, only `MmIsAddressValid` gate | **R (kernel)** — `auth` |
| 789 | `140002180` | Command on path string | `sub_1400037AC((WCHAR*)(cmd+24))` | **L/OOB** (unbounded wcslen on buffered input; same class as 790) |
| 790 | `140003508` | Command on path string (image-name registry) | `do{++v5;}while(*(WORD*)(cmd+24+2v5));` → `sub_1400074E8` | **OOB** (unbounded wcslen past SystemBuffer) |
| 791 | `140003018` | **`ZwQueryInformationProcess` proxy** with user handle + user-controlled info class + user output buffer | `ZwQueryInformationProcess` | **A** (Zw sets PreviousMode=Kernel → handle/info-class access checks bypassed); some info classes (e.g. `ProcessImageFileName`, `ProcessDebugPort`) yield data normally gated by `PROCESS_QUERY_INFORMATION` even with a `QUERY_LIMITED_INFORMATION` handle |
| 792 | `1400027F0` | Generic per-process op | `sub_140007874` ladder → `sub_1400086C0` | **A** (same ladder issue, op-specific severity) |
| 793 | `140002990` | Process op returning a pointer | `sub_140007874` ladder → `sub_1400087B8` | **A/L** |
| 794 | `140002730` | Process op into user buffer | `sub_140007874` ladder → `sub_140008400` | **A/L** |
| 796 | `1400021FC` | Read file by path (kernel context), return DWORD checksum | `ZwOpenFile(OBJ_KERNEL_HANDLE)` + `ZwReadFile` | **L** (kernel-mode read bypasses caller's DACL; attacker-controlled path; weak disclosure channel — only sum-of-DWORDs) |
| 797 | `140002954` | Look up per-PID flags (any PID) | `sub_140006204` | **L** (disclose trust table entries) |
| 798 | `1400020D8` | Fill user buffer | `sub_1400054E4` | — (size-checked) |
| 799 | `140002A10` | Returns constant `30` | — | — |
| 800 | `140001FF8` | Close handle in another process | `sub_140007874` ladder → `KeStackAttachProcess` → `ObSetHandleAttributes` + `ZwClose` on `cmd[+32]` handle value inside target | **A/W-ish** (can close arbitrary handle inside another process once handle is resolved via ladder) |
| 801 | `140003658` (→ `sub_140009C5C`) | Trigger win32k SSDT-index capture / internal init | `MmGetSystemRoutineAddress`, NT/win32k section parse | — (no user args) |
| 802 | `1400036D0` | Acquire+release internal mutex | `KeWaitForSingleObject`/`KeReleaseMutex` | — |
| 803 | `140003658` (same as 801) | Same initializer | — | — |
| 804 | `140003694` | Per-PID win32k affinity op | `sub_14000AB34` (`PsLookupProcessByProcessId` → attach → win32k call via captured function pointer) | **A** (operates on any PID; narrow effect: sets `NtUserSetWindowDisplayAffinity`-equivalent) |
| 805 | `140002870` | **Page-table walk via physical-memory read** — returns PTE for (handle-resolved process, VA) | `sub_140007778` (ladder) → `sub_140006598` (opens `\Device\PhysicalMemory` / resolves `MmCopyMemory`) → `sub_14000646C` (4× `sub_140006648`) | **A/L** — PFN leak on kernel VAs breaks KASLR; on user VAs leaks phys layout (details in deep-dive below) |
| 806 | `140002E88` | No-op probe | — | — |
| 807 | `140001E14` | **Inject driver-provided payload into resolved process** | `sub_140009FF4`→`sub_14000A6C8`→`sub_14000A738`→`sub_14000A028`→`sub_14000A7A4` | **X** (driver-owned payload, `PROCESS_ALL_ACCESS` via `ObOpenObjectByPointer(KernelMode)`, `RtlCreateUserThread`/`NtCreateThreadEx`); target chosen by attacker |
| 808 | `140001ED4` | Same injector, alternate entry | `sub_14000A6C8`→… | **X** |
| 809 | `140002704` | Returns constant `822` | — | — |
| 810 | `140002F1C` | **`ZwCreateFile` with attacker-controlled path & access mask in kernel context** | `ZwCreateFile` (OBJ_CASE_INSENSITIVE only, handle returned to caller's *user* handle table) | **A/W** (kernel-mode open bypasses caller's DACL; full `DesiredAccess` from user — read, write, delete, set-security on any file) — `auth` |
| 811 | `140001F14` | Injector wrapper | `sub_14000A738` → driver payload | **X** |
| 812 | `1400021C0` | Info struct fill | `sub_1400061C0` | — |
| 813 | `140003458` | **Populate trust-cache entry**: add `{path=cmd+28 WCHARs, flag=cmd+24 DWORD}` | `sub_14000CA84` → `sub_14000CAC0` → `sub_14000CB18` (writes `qword_1400220F8[count++]`); also `RtlInitUnicodeString` (unbounded wcslen) | **A — CACHE POISON.** Unauth'd. Plant entry with flag bit 3 set → any child process launched from that exact NT path is stamped with bit 3 at `PsSetCreateProcessNotifyRoutine` time. Independent auth-bypass path. Also **OOB** (unbounded wcslen). |
| 814 | `140001F78` | Info fill | `sub_140003C54` | — |
| 815 | `140001E54` | Injector wrapper (driver payload) | `sub_14000A028` → `sub_14000A7A4` | **X** |
| 816 | `140002334` | Win32k global state fill | reads `qword_140022068[48]+*` kernel ptrs | **L** (leaks win32k internal field values / offsets) |
| 817 | `140001FB4` | Config query | `sub_140003D28` | — |
| 818 | `140003140` | `MmSecureVirtualMemory(Ex)` wrapper | `MmSecureVirtualMemory` | — (legitimate use; no user-RW granted) |
| 819 | `140002EB0` | Process fingerprint | `sub_140007874` ladder → `sub_140001A5C` | **A/L** |
| 820 | `140001E94` | **Inject attacker-supplied shellcode into arbitrary process** | `sub_14000A1AC` → `sub_14000A330` | **X** (see below) |
| 821 | `14000361C` | Internal op | `sub_140004CF0(DWORD)` | — |

---
