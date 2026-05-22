# Anti-Analysis

## Trigger
When the binary prevents or complicates analysis through anti-debugging, anti-VM, anti-DBI, integrity checks, or anti-disassembly techniques. Also when unpacking, deobfuscation, or VM handler analysis is required.

## Attack Surface
Protection mechanisms: ptrace-based anti-debug, /proc filesystem checks, timing verification (rdtsc, clock_gettime), TLS callbacks (Windows -- run before main), PEB/NtQueryInformationProcess (Windows), hardware breakpoint detection (DR0-DR3), INT3 scanning (software breakpoint detection), code self-hashing (CRC/SHA over .text), signal-based logic obfuscation (SIGTRAP, SIGFPE, SIGSEGV handlers), VMProtect/Themida virtualization, OLLVM control-flow flattening, MBA expressions, opaque predicates, direct syscall evasion, fork+pipe parent-child anti-analysis, multi-thread anti-debug with watchdog threads.

## Decision Tree
Identify protection type (strings, section names, behavior) -> select bypass strategy (LD_PRELOAD, Frida hook, binary patch, emulation, hardware breakpoints) -> apply bypass -> verify code is reachable -> proceed with analysis.

Check for anti-debug early: run `strace ./binary` and look for ptrace calls, `/proc/self/status` reads, or alarm signals. Run `strings binary | grep -iE "vmp|themida|upx|obfuscat|ollvm|obsidium"` for packer/obfuscator identification. Check PE TLS directory for callbacks. Look for `rdtsc`, `cpuid` instructions in disassembly.

## Techniques

### Linux Anti-Debug Bypass

**Self-ptrace (PTRACE_TRACEME):** The binary calls `ptrace(PTRACE_TRACEME)` and if it returns -1 (already traced), it exits. Bypasses:
```bash
# 1. LD_PRELOAD hook
LD_PRELOAD=./hook.so ./binary

# 2. pwntools patch
python3 -c "
from pwn import *
elf = ELF('./binary', checksec=False)
elf.asm(elf.symbols.ptrace, 'xor eax, eax; ret')
elf.save('patched')
"

# 3. GDB syscall catch
(gdb) catch syscall ptrace
(gdb) commands
> set $rax = 0
> continue
> end
```

**Double-ptrace (fork child ptrace-attaches parent):** Kill the watchdog child process, then attach debugger normally. The child sits in a waitpid loop keeping the parent traced.

**/proc filesystem checks (TracerPid):** The binary reads `/proc/self/status` looking for `TracerPid:\t0`. Bypasses:
```bash
# Mount namespace isolation
unshare -m bash -c 'mount --bind /dev/null /proc/self/status && ./binary'

# GDB: redirect fopen
(gdb) b fopen
(gdb) commands
> set {char[20]}$rdi = "/dev/null"
> continue
> end
```

**Timing checks (rdtsc):** 
```
start = __rdtsc(); ... suspicious_code ...; delta = __rdtsc() - start; delta > THRESHOLD -> exit
```
Bypass: NOP the rdtsc, Frida hook clock_gettime to return constant, or use `LD_PRELOAD=faketime`:
```bash
LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2024-01-01" ./binary
```

**Signal-based anti-debug:**
```
SIGTRAP through INT3: debugger catches, handler never runs -> debugger detected
SIGALRM timeout: alarm(5); kill(self); if analysis slow
SIGSEGV for real logic: handler runs transform, code only works under signal handler
```
Bypass in GDB:
```bash
(gdb) handle SIGTRAP nostop pass
(gdb) handle SIGALRM ignore
(gdb) handle SIGSEGV nostop pass
```

**Syscall-level evasion:** Binary issues direct `syscall` instead of libc wrapper to bypass LD_PRELOAD hooks. Bypass: `catch syscall 101` (ptrace on x86_64) in GDB.

**SIGFPE handler mprotect mutation:** Binary installs SIGFPE handler, then deliberately raises SIGFPE; handler calls `mprotect` to make .text writable and mutates code. Bypass: `handle SIGFPE nostop noprint pass` in GDB, trace handler steps.

### Windows Anti-Debug Bypass

**PEB checks (BeingDebugged, NtGlobalFlag):**
```
PEB+0x2 = BeingDebugged flag (1 = debugged)
PEB+0xBC (64-bit) = NtGlobalFlag (0x70 = debugging heap flags)
```
Bypass: ScyllaHide plugin auto-patches PEB fields in x64dbg.

**NtQueryInformationProcess calls:**
```
ProcessDebugPort (0x7): non-zero = debugger
ProcessDebugObjectHandle (0x1E): STATUS_SUCCESS = debugger  
ProcessDebugFlags (0x1F): 0 = debugger
```
Bypass: Hook ntdll, or use ScyllaHide.

**TLS callbacks:** Functions registered in PE TLS directory execute BEFORE entry point. Often check IsDebuggerPresent and call ExitProcess. Bypass: Break on TLS in x64dbg (Options -> Events -> TLS Callbacks), or patch TLS directory entry.

**Hardware breakpoint detection:** `GetThreadContext(..., CONTEXT_DEBUG_REGISTERS)` reads DR0-DR3. Bypass: Use software breakpoints only, or hook GetThreadContext.

**INT3 scanning / code self-hashing:** Binary scans .text for INT3 (0xCC) or computes CRC/SHA over code section. Bypass: Use hardware breakpoints only, or patch the hash comparison to always match. For self-hashing in a watchdog thread, kill the watchdog or patch its sleep to infinite.

### Anti-VM / Anti-Sandbox Bypass

**CPUID hypervisor bit:** Check ECX bit 31 for hypervisor present. Bypass: Patch CPUID result, or use bare metal for analysis.

**MAC address detection:** VMware (00:0C:29, 00:50:56), VirtualBox (08:00:27), Hyper-V (00:15:5D), QEMU (52:54:00). Bypass: Use a custom VM network config or bare metal.

**Resource checks (low CPU count, RAM, disk):** Bypass: Configure VM with 4+ CPUs, 8GB+ RAM, 100GB+ disk.

### Anti-DBI Bypass

**Frida detection:** Check `/proc/self/maps` for frida strings, port 27042 for frida-server, function prologue bytes for inline hooks. Bypass: Hook `strstr` to return 0 when needle contains "frida" or "gadget":
```javascript
Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onLeave(retval) {
        if (this.needle && this.needle.includes("frida"))
            retval.replace(ptr(0));
    }
});
```

### Anti-Disassembly Techniques

**Opaque predicates:** Condition that always evaluates the same way but looks data-dependent. Example: `x^2 mod 2 == 0` for any x. Identification: Z3/SMT can prove branch is always/never taken. Deobfuscation tools: D-810 (IDA), GOOMBA (Ghidra), Miasm.

**Junk bytes / overlapping instructions:** Insert bytes that linear disassemblers interpret as instruction start but execution jumps past them. Fix: Use graph-mode disassembly (Ghidra/IDA handle this well). Manually undefine and re-analyze from the real entry point.

**Jump-in-the-middle:** Jump into the middle of a multi-byte instruction. Example: `eb 01 e8 90` -- the `e8` looks like a CALL to linear disassembler but execution jumps via `eb 01` to land on `90` (NOP).

**Control flow flattening (OLLVM):** Replace structured control flow with a switch dispatcher and state variable. Deobfuscation: Trace the state variable transitions at runtime with GDB, map the graph. Use D-810 or Miasm for automated deobfuscation.

**VMProtect/Themida:** Code virtualized into custom bytecode. Identify VM entry (pushad-like sequences), locate handler table (large indirect jump), trace handlers dynamically. For CTF, focus on tracing operations on input rather than full devirtualization. For Themida: dump unpacked code at OEP using ScyllaHide and Scylla in x64dbg.

**Mixed Boolean-Arithmetic (MBA):** Replace simple ops with complex algebraic equivalents. Common patterns and simplifications:
```
(x ^ y) + 2*(x & y) == x + y
(x | y) & ~(x & y) == x ^ y
~(~x & ~y) == x | y
```

### Unpacking

**UPX:** 
```bash
upx -d packed -o unpacked
```

**Custom packers:** Set breakpoint after unpacking stub, dump memory, fix PE/ELF headers.

**PyInstaller:**
```bash
python pyinstxtractor.py binary.exe
```

**Pyarmor 8/9:** Use Lil-House/Pyarmor-Static-Unpack-1shot tool for static unpacking without execution. Payload starts with `PY` + six digits.

**Parent-patched child binary:** When parent uses `process_vm_writev` to write real instructions into child process full of INT3 traps, use strace to capture all the writes:
```bash
strace -f -e trace=process_vm_writev -e write=all -o trace.log ./binary
```
Parse the log to extract `(address, bytes)` pairs and apply in IDA/Ghidra.

### LD_PRELOAD Hook Template

For intercepting libc functions to bypass environment checks:
```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/ptrace.h>

long int ptrace(enum __ptrace_request req, ...) {
    long int (*orig)(enum __ptrace_request, pid_t, void*, void*);
    orig = dlsym(RTLD_NEXT, "ptrace");
    return 0;  // Always succeed
}
```
```bash
gcc -shared -fPIC -ldl hook.c -o hook.so
LD_PRELOAD=./hook.so ./binary
```

## Bypass
Universal bypass checklist: (1) Identify all checks -- search for ptrace, IsDebuggerPresent, rdtsc, cpuid, /proc/self, SIGTRAP, alarm. (2) Static patching -- NOP/patch checks before running. (3) LD_PRELOAD -- hook libc functions. (4) ScyllaHide -- Windows PEB/NTAPI patching. (5) Emulation -- no debugger artifacts. (6) Hardware breakpoints -- avoid INT3/CRC detection. (7) Kill watchdog threads for multi-threaded anti-debug.

## Verification
Run patched/hooked binary and confirm it reaches the main logic without triggering anti-debug exits. Verify by stepping through checks in GDB with `catch syscall ptrace` or `b ptrace@plt`. For unpacked binaries, confirm OEP is reached and code sections are correct.

## Pitfalls
Multiple anti-analysis layers may interact -- patching one check may activate another. TLS callbacks run before main and may not be visible in standard disassembly without checking the PE TLS directory. Direct syscalls bypass LD_PRELOAD entirely. Continuous self-hashing watchdog threads need to be killed before they zero out the flag buffer. Emulation (Unicorn/Qiling) bypasses most anti-debug but may miss edge cases in syscall behavior.
