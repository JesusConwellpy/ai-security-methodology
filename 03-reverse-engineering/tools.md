# Tools

## Trigger
When selecting the appropriate tool for a reverse engineering task based on binary type, architecture, protections, and analysis phase.

## Attack Surface
Tool selection depends on: analysis phase (initial triage, static, dynamic, emulation, deobfuscation), binary format (ELF, PE, Mach-O, WASM, APK, .NET, Python bytecode, firmware), architecture (x86/x64, ARM/Thumb/AArch64, MIPS, RISC-V, PPC, Z80, Xtensa), protections (packed, VM-protected, obfuscated), and workflow (interactive GUI, headless scripting, automated binary analysis, debugging).

## Decision Tree
File type -> tool chain selection -> initial scan -> static decompilation -> dynamic validation -> solve. For unknown formats: start with `file` and `strings`. For known: use format-specific tool. Match tool capability to protection level.

## Techniques

### Initial Triage Tools

```bash
file binary                    # Type and architecture
checksec --file=binary         # Security features (PIE, NX, RELRO, Canary)
strings binary | grep -i flag  # Quick win
rabin2 -I binary               # radare2 info
rabin2 -z binary               # Strings with addresses
readelf -S binary              # Section listing
readelf -s binary              # Symbols
nm binary                      # Symbol names (unstripped)
objdump -d binary              # Full disassembly
objdump -M intel -d binary     # Intel syntax
xxd binary | grep -i flag      # Hex-level search
ltrace ./binary                # Library call trace
strace -f -s 500 ./binary      # Syscall trace
```

### Ghidra

Best-in-class free decompiler with Sleigh-based intermediate representation. Supports x86, ARM, AArch64, MIPS, PPC, RISC-V, 6502, 8051, and many more.

**Headless mode:** `analyzeHeadless /path/to/project tmp -import binary -postScript script.py -deleteProject`

**Emulator helper for runtime decryption:**
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeMemory(dataAddress, encryptedBytes);
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);
byte[] decrypted = emu.readMemory(outputAddress, length);
```

**Decompiler API for bulk analysis:**
```python
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
for func in currentProgram.getFunctionManager().getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompiledFunction():
        code = result.getDecompiledFunction().getC()
        if "strcmp" in code: print(f"Found at {func.getEntryPoint()}")
```

**Patching workflow:** Find check -> Ctrl+Shift+G (patch instruction) -> modify conditional jump (JNZ/JZ swap) -> export as Original File -> `chmod +x`.

**Community plugins:** GOOMBA (deobfuscation), golang-loader (Go symbol recovery), BinExport (for binding with BinDiff).

### IDA Pro

Industry-standard disassembler with Hex-Rays decompiler (best-in-class x86/x64 decompilation).

**D-810 plugin:** Pattern-based deobfuscation from the Hex-Rays team. Simplifies MBA expressions, removes opaque predicates, eliminates dead code, flattens control flow.

**IDAPython automation:**
```python
import idc
for func_ea in idautils.Functions():
    name = idc.get_func_name(func_ea)
    # Analyze, rename, extract constants
```

**Binary diffing:** Use BinExport to export `.BinExport` files, then bindiff against patched/original versions to reveal vulnerabilities or hidden functionality.

### radare2 / Rizin

Open-source reverse engineering framework with CLI and GUI (Cutter).

```bash
r2 -d ./binary     # Debug mode
aaa                # Analyze all
afl                # List functions
pdf @ main         # Print disassembly of main
db 0x401234        # Set breakpoint
dc                 # Continue
dr eax=0           # Modify register
ood                # Restart process
VV                 # Visual graph mode
```

**r2pipe automation:**
```python
import r2pipe
r2 = r2pipe.open('./binary', flags=['-d'])
r2.cmd('aaa')
for char in range(256):
    r2.cmd('ood')
    r2.cmd(f'dr eax={char}')
    output = r2.cmd('dc')
    if 'correct' in output:
        print(f"Found: {chr(char)}")
```

**r2frida (radare2 + Frida):**
```bash
r2 frida://spawn/./binary
\ii                    # List imports
\dt strcmp             # Trace strcmp
\dm                    # Memory maps
```

**Cutter GUI:** Built-in Ghidra decompiler (r2ghidra), graph view, hex editor, integrated scripting console. Free and open-source.

### Binary Ninja

Interactive disassembler with clean Python API and HLIL (High-Level IL) for analysis.

```python
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)
```

Headless patching:
```python
bv.write(0x401234, b"\x90" * 5)    # NOP
bv.write(0x401234, b"\xb8\x01\x00\x00\x00\xc3")  # mov eax,1; ret
bv.save("patched")
```

### Frida (Dynamic Instrumentation)

In-process JavaScript-based hooking. Best for bypassing anti-debug and runtime data extraction.

```bash
frida -f ./binary -l hook.js --no-pause
frida -p $(pidof binary) -l hook.js
```

Key capabilities: function hooking (Interceptor.attach), function replacement (Interceptor.replace), memory scanning (Memory.scan), code patching (Memory.patchCode), instruction tracing (Stalker). For r2frida integration, see radare2 section.

### GDB (GNU Debugger)

Standard Linux debugger with Python scripting.

**Setup with pwndbg:**
```bash
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
```

**Key commands:** `start` (PIE-safe entry), `b *main+OFFSET`, `x/s $rsi`, `info registers`, `watch *(int*)ADDR`, `catch syscall ptrace`.

**Reverse execution with rr:** `rr record ./binary && rr replay` for reverse-continue and reverse-stepi.

### angr (Symbolic Execution)

Automated path exploration for flag-checking binaries.

```python
import angr
proj = angr.Project('./binary', auto_load_libs=False)
simgr = proj.factory.simgr()
simgr.explore(find=SUCCESS_ADDR, avoid=FAIL_ADDR)
if simgr.found:
    print("Flag:", simgr.found[0].posix.dumps(0))
```

CFG recovery: `cfg = proj.analyses.CFGFast()`. Hook expensive functions with custom SimProcedures.

### Unicorn Engine

CPU-level emulation without OS layer. Supports x86/x64, ARM/Thumb/AArch64, MIPS, PPC, RISC-V, Sparc, m68k.

```python
from unicorn import *
from unicorn.x86_const import *
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)
mu.mem_write(0x400000, code)
mu.reg_write(UC_X86_REG_RSP, stack_addr)
mu.emu_start(start, end)
```

Use hooks (`UC_HOOK_CODE`) for register tracing and state inspection.

### Qiling Framework

Unicorn + OS layer (syscalls, filesystem, registry). Supports Linux, Windows, macOS, Android, UEFI, DOS.

```python
from qiling import Qiling
ql = Qiling(["./binary"], "rootfs/x8664_linux")
ql.os.set_syscall("ptrace", lambda ql, *args: 0)  # Bypass ptrace
ql.run()
```

Best for: foreign-architecture binaries, IoT firmware, heavy anti-debug bypass.

### x64dbg (Windows Debugger)

Open-source Windows debugger. ScyllaHide plugin for anti-debug bypass. Scylla plugin for import reconstruction on packed binaries. Snowman decompiler for quick pseudo-C.

### LLDB (LLVM Debugger)

Primary debugger for macOS/iOS. Also works on Linux. Structured Python API.

```bash
lldb ./binary
(lldb) b main
(lldb) run
(lldb) register read
(lldb) memory read 0x401000 -c 32
```

### Decompiler Comparison Tools

**dogbolt.org:** Runs multiple decompilers (Hex-Rays, Ghidra, Binary Ninja, angr, RetDec, Snowman, dewolf, Reko) on the same binary side-by-side. Essential for cross-referencing decompiler outputs.

**RetDec:** Free LLVM-based decompiler supporting x86, ARM, MIPS, PPC, PIC32. Produces compilable C code.
```bash
retdec-decompiler binary
```

### Android / Mobile Tools

**APKTool:** `apktool d app.apk -o decoded/` -- decodes XML resources, extracts DEX.

**Jadx:** `jadx app.apk` -- decompiles DEX to Java source.

**Blutter:** For Flutter APK Dart AOT analysis: `python3 blutter.py path/to/app/lib/arm64-v8a out_dir`.

**abc-decompiler:** For HarmonyOS HAP/ABC bytecode: `java -cp "./jadx-dev-all.jar" jadx.cli.JadxCLI -m simple -d "out" "modules.abc"`.

### .NET Tools

**dnSpy:** Full decompilation + debugging. For ConfuserEx: break on `<Module>.cctor`, wait for decrypt, Save Module.

**ILSpy:** Read-only decompilation. **de4dot:** Symbol cleanup after unpacking.

### Python Bytecode Tools

```python
import marshal, dis
with open('file.pyc', 'rb') as f:
    f.read(16)  # Skip header
    code = marshal.load(f)
    dis.dis(code)
```

**Pyarmor static unpack:** `python /path/to/oneshot/shot.py /path/to/scripts -o /path/to/output`.

**pycdc:** For Python 3.9+ bytecode: `git clone https://github.com/zrax/pycdc && cmake . && make`.

### WASM Tools

```bash
wasm2c checker.wasm -o checker.c    # Decompile to C
wasm2wat main.wasm -o main.wat      # Binary to text
wat2wasm main.wat -o patched.wasm   # Recompile after patching
```

### Firmware / IoT Tools

**binwalk:** `binwalk -Me firmware.bin` for recursive firmware extraction.

**SquashFS:** `unsquashfs -d output/ root.sqfs`.

**Cross-architecture emulation:** `qemu-arm -L /usr/arm-linux-gnueabihf/ ./binary`; `qemu-system-x86_64 -kernel bzImage -initrd initrd.cpio -s -S` for kernel debugging.

### Side-Channel / Oracle Tools

**Intel Pin:** `./pin -t inscount0.so -- ./binary` for instruction-counting side channel.

**faketime:** `LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="2024-01-01" ./binary`.

**libSegFault.so:** `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libSegFault.so ./target` for register dump at crash.

### Deobfuscation Frameworks

| Tool | Platform | Capability |
|------|----------|------------|
| D-810 | IDA | MBA simplification, opaque predicate removal, CFF deobfuscation |
| GOOMBA | Ghidra | P-Code-level obfuscation matching |
| Miasm | Python | Symbolic execution, IR lifting, expression simplification |
| Triton | Python/C++ | Dynamic symbolic execution, taint tracking |
| Manticore | Python | Symbolic execution, EVM support |
| Arybo/SiMBA | Python | MBA expression simplification |

### Cryptography / Math Tools

**Z3 (SMT solver):** For constraint-based flag recovery. Supports bitvector and integer logic.

**boolector:** QF_BV bitvector solver, 10-100x faster than Z3 for hash reversal puzzles.

**PuLP:** ILP/LP solver for linear arithmetic constraint extraction from comparison binaries.

**SageMath:** CVP/LLL lattice reduction for constrained integer validation.

**SMT2 for hash reversal:**
```smt
(set-logic QF_BV)
(declare-fun input () (_ BitVec 64))
(assert (= (hash input) #xdeadbeefcafef00d))
(check-sat) (get-model)
```

### Binary Modification Tools

**LIEF:** Cross-format binary patching. Add sections, modify headers, patch imports.
```python
binary = lief.parse("binary")
section = lief.ELF.Section(".patch"); section.content = list(b"\x90"*0x100)
binary.add(section)
binary.write("patched")
```

**pwntools:** `elf.asm(elf.symbols.ptrace, 'ret')` for function replacement.

## Verification
Test tool output by cross-referencing decompilations across multiple tools (dogbolt.org). Verify key findings (expected values, algorithm logic) by implementing inverse functions and testing against known outputs. For debugging tools, confirm breakpoints fire at expected code locations.

## Pitfalls
Ghidra may miss Go strings without golang-loader plugin. IDA Free has limited decompilation. Binary Ninja's Python API is powerful but the free version is cloud-based. Unicorn lacks OS syscall support -- use Qiling when file I/O is needed. Radare2 learning curve is steep but r2pipe enables powerful scripting. Frida can be detected via `/proc/self/maps` scans -- use early-init gadget. Angr path explosion requires function hooking for complex binaries. Decompiler comparison catches decompiler bugs but requires manual validation.
