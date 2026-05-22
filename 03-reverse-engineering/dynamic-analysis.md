# Dynamic Analysis

## Trigger
When the binary is running or can be run in an emulated/dynamically-instrumented environment. Use when static analysis is blocked by packing, obfuscation, anti-disassembly, or cross-architecture constraints. Also use for runtime data extraction (decryption keys, comparison targets, deobfuscated code).

## Attack Surface
Executable characteristics requiring dynamic analysis: packed/encrypted binaries (UPX, VMProtect, Themida, custom), self-modifying code, anti-debug checks, anti-VM triggers, runtime-computed decryption keys, multi-stage shellcode loaders, obfuscated control flow, signal-handler-based logic, thread-based anti-debug, time-locked execution, fork-based parent-child anti-analysis.

## Decision Tree
Run once -> observe behavior (ltrace/strace) -> identify anti-debug -> hook/patch -> attach debugger or Frida -> set breakpoints on comparison functions -> extract runtime values -> reinforce with symbolic execution for multi-path exploration.

Start with `ltrace ./binary` and `strace -f -s 500 ./binary` to capture library calls and syscalls without any config. Many challenges leak the flag through these alone, especially `strcmp` calls. If the binary hangs or shows no output, check for `sleep`, `alarm`, `usleep` calls in strace output. If it forks, add `-f` to strace.

## Techniques

### FRIDA (Dynamic Instrumentation)

Hooks into running processes via JavaScript, bypasses most anti-debug by running in-process:

```javascript
// Hook strcmp to capture comparisons
Interceptor.attach(Module.findExportByName(null, "strcmp"), {
    onEnter(args) {
        this.arg0 = Memory.readUtf8String(args[0]);
        this.arg1 = Memory.readUtf8String(args[1]);
        console.log(`strcmp("${this.arg0}", "${this.arg1}")`);
    }
});
```

```bash
frida -f ./binary -l hook.js --no-pause
frida -p $(pidof binary) -l hook.js
```

Bypass anti-debug via Frida:
```javascript
// Bypass ptrace(TRACEME)
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter(args) { this.request = args[0].toInt32(); },
    onLeave(retval) {
        if (this.request === 0) retval.replace(ptr(0));
    }
});

// Bypass time-based checks
Interceptor.attach(Module.findExportByName(null, "clock_gettime"), {
    onLeave() {
        var ts = this.context.rsi;
        Memory.writeU64(ts, 0);
        Memory.writeU64(ts.add(8), 0);
    }
});
```

Memory scanning for flag patterns:
```javascript
Process.enumerateRanges('r--').forEach(function(range) {
    Memory.scan(range.base, range.size, "66 6c 61 67 7b", { // "flag{"
        onMatch(address) {
            console.log("FLAG at:", address, Memory.readUtf8String(address, 64));
        }
    });
});
```

Function replacement to skip validation:
```javascript
var checkFlag = Module.findExportByName(null, "check_flag");
Interceptor.replace(checkFlag, new NativeCallback(function(input) {
    return 1; // Always valid
}, 'int', ['pointer']));
```

For Android/iOS: Frida hooks Java methods and native JNI functions. Bypass certificate pinning by intercepting SSL verification functions.

### GDB

Essential for step-through debugging of Linux ELF binaries:

```bash
gdb ./binary
run                      # Start
b *0x401234              # Breakpoint at address
b *main+0x100            # Relative breakpoint (PIE safe)
c                        # Continue
si                       # Step instruction
ni                       # Next instruction
x/s $rsi                 # Examine string
x/20x $rsp               # Stack dump
info registers           # Show all registers
set $eax=0               # Modify register
```

For PIE binaries, use `start` before setting relative breakpoints to resolve base.

Conditional breakpoints:
```bash
b *0x401234 if $rax == 0x41
b *0x401234 if *(char*)$rdi == 'f'
```

Logging without stopping:
```bash
b *0x401234
commands
  silent
  printf "rax=%lx rdi=%lx\n", $rax, $rdi
  continue
end
```

Watchpoints for data changes:
```bash
watch *(int*)0x601050         # Write
rwatch *(int*)0x601050        # Read
awatch *(int*)0x601050        # Read or write
```

pwndbg extensions (for CTF):
```
context           # Registers + stack + code + backtrace
vmmap             # Memory map
search -s "flag{" # Memory string search
telescope $rsp 20 # Smart stack dump
got               # GOT entries
plt               # PLT entries
```

Reverse debugging with `rr`:
```bash
rr record ./binary
rr replay
(gdb) reverse-continue   # Run backward
(gdb) reverse-stepi      # Step backward
```

GDB Python scripting for brute-force flag extraction:
```python
import gdb, string

class CmpLogger(gdb.Breakpoint):
    def stop(self):
        frame = gdb.selected_frame()
        rdi = int(frame.read_register("rdi"))
        rsi = int(frame.read_register("rsi"))
        buf1 = gdb.selected_inferior().read_memory(rdi, 32).tobytes()
        buf2 = gdb.selected_inferior().read_memory(rsi, 32).tobytes()
        print(f"cmp({buf1!r}, {buf2!r})")
        return False  # Don't stop, just log
```

### x64dbg (Windows Debugger)

For Windows PE binaries: breakpoints (F2), step into (F7), step over (F8), run (F9). Use ScyllaHide plugin for anti-debug bypass (PEB, NtQueryInformationProcess). Use Scylla plugin for IAT reconstruction on packed binaries. Snowman decompiler plugin for quick pseudo-C.

### LLDB (macOS/iOS Debugger)

```bash
lldb ./binary
(lldb) b main
(lldb) run
(lldb) si / ni
(lldb) register read
(lldb) memory read 0x401000 -c 32
(lldb) dis -n main
```

### ANGR (Symbolic Execution)

Automated path exploration for flag-checker binaries:

```python
import angr, claripy

proj = angr.Project('./binary', auto_load_libs=False)
FIND_ADDR = 0x401234   # Success path
AVOID_ADDR = 0x401256  # Failure path

simgr = proj.factory.simgr()
simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

if simgr.found:
    print("Flag:", simgr.found[0].posix.dumps(0))
```

Constrained symbolic input:
```python
flag_chars = [claripy.BVS(f'f{i}', 8) for i in range(32)]
flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
state = proj.factory.entry_state(stdin=flag)
for c in flag_chars:
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)
state.solver.add(flag_chars[0] == ord('f'))
```

Deal with path explosion by hooking expensive functions (crypto, I/O) and using DFS exploration:
```python
simgr.use_technique(angr.exploration_techniques.DFS())
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
```

### UNICORN EMULATION

CPU-level emulation for self-modifying or foreign-architecture code:

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code_bytes)
mu.mem_map(0x7fff0000, 0x10000)
mu.reg_write(UC_X86_REG_RSP, 0x7fff0000 + 0xff00)
mu.emu_start(start_addr, end_addr)
```

Register tracing hook:
```python
def hook_code(uc, address, size, user_data):
    if address == TARGET_ADDR:
        rsi = uc.reg_read(UC_X86_REG_RSI)
        print(f"0x{address:x}: rsi=0x{rsi:016x}")
mu.hook_add(UC_HOOK_CODE, hook_code)
```

Mixed-mode emulation (64->32 via retf): create a second UC_MODE_32 emulator, copy GPRs, EFLAGS, and XMM registers before switching.

### QILING FRAMEWORK

Cross-platform emulation with OS-level support (syscalls, filesystem):

```python
from qiling import Qiling
ql = Qiling(["./binary"], "rootfs/x8664_linux")
```

Hook syscalls and addresses for anti-debug bypass:
```python
@ql.hook_syscall(name="ptrace")
def hook_ptrace(ql, request, pid, addr, data):
    return 0  # Always succeed

@ql.hook_address(0x401234)
def skip_check(ql):
    ql.arch.regs.rax = 0
```

Advantages: no debugger artifacts (bypasses all anti-debug by default), cross-platform (ARM, MIPS, RISC-V on x86 host), snapshot/restore, import fuzzing.

### SIDE-CHANNEL TECHNIQUES

**Intel Pin instruction-counting:** Use `inscount0.so` tool to measure instruction count per input. Correct characters cause deeper execution. Pair with genetic algorithm for self-modifying multi-stage decryptors.

**LD_PRELOAD memcmp hook:** Replace memcmp to return match count instead of -1/0/1, converting any comparison-based validation into a byte-by-byte oracle:
```c
int memcmp(const char *s1, const char *s2, int n) {
    int cnt = 0;
    for (int i = 0; i < n; ++i) {
        if (s1[i] == s2[i]) cnt++;
        else break;
    }
    return cnt;
}
```

**LD_PRELOAD time freeze:** Override `time()` to return a constant, freezing PRNG-based cipher into deterministic byte-by-byte oracle.

**SIGFPE signal counting via strace:** Count SIGFPE signals per character -- correct input produces more signals. Use `strace -e signal=SIGFPE`.

## Bypass
Combine anti-debug bypasses: LD_PRELOAD hooks for libc functions, Frida for in-process hooking, Qiling/Unicorn for artifact-free emulation. Patch checks directly with pwntools: `elf.asm(elf.symbols.ptrace, 'ret')`. Use hardware breakpoints to avoid INT3 detection. For self-modifying code, use Unicorn emulation. For multi-threaded anti-debug, kill watchdog threads.

## Verification
Confirm flag extraction by matching against expected format. Verify runtime-extracted keys by decrypting ciphertext independently. For symbolic execution solutions, re-run the binary with the found input to confirm success path reached. For Frida hooking, compare hooked vs unhooked behavior to ensure hooks fire.

## Pitfalls
Frida detection can be evaded by checking `/proc/self/maps` for frida libraries -- use `frida-gadget` as early-init shared library. Angr path explosion from complex loops can be mitigated by hooking those functions. Unicorn does not emulate OS syscalls -- use Qiling instead when file I/O or network is needed. Mixed-mode (64/32) transitions via `retf` require careful mode switching. Fork-based anti-debug (parent watches child via ptrace) needs the forked watchdog process killed before attaching a debugger.
