# Static Analysis

## Trigger
When the binary is ELF/PE/Mach-O/WASM/APK/DEX/bytecode and no dynamic execution is available or desired. Also when the target is packed, obfuscated, or cross-architecture and emulation is unavailable.

## Attack Surface
Binary characteristics to identify before analysis: format (ELF, PE, Mach-O, WASM, APK, flat binary, firmware blob), architecture (x86/x64, ARM/Thumb, MIPS, RISC-V, AArch64, Xtensa, Z80), protections (PIE, NX, RELRO, stack canary, FORTIFY), packers (UPX, VMProtect, Themida, custom), obfuscation (OLLVM, MBA, control-flow flattening, opaque predicates, string encryption), and language/runtime (Go, Rust, .NET, Python, compiled Unity IL2CPP, Swift, Kotlin/Native).

## Decision Tree
file(1) -> architecture detection -> section/symbol scan -> tool selection -> entry point ID -> function enumeration -> decompile -> identify comparisons -> extract constants -> solve.

Run `file binary` and `strings binary | head -50` first. If strings show full function names and source paths, the binary is unstripped -- use `nm` and `readelf -s` for symbol recovery. Check for `.net`, `__swift5_*`, `go.buildid`, `core::panicking`, `kotlin.Metadata` for language identification. Use `strings binary | grep -i "upx\|vmp\|themida"` for packer detection. If `readelf -S` crashes but `readelf -l` works, section headers are corrupted -- zero out `e_shoff` in the ELF header to bypass.

## Techniques

### GHIDRA

Headless analysis for batch/automated workflows:
```bash
analyzeHeadless /path/to/project tmp -import binary -postScript script.py -deleteProject
```

Python/Jython scripting in the Script Manager allows programmatic decompilation, XREF enumeration, and function renaming. Use the decompiler interface to bulk-search for comparison patterns:
```python
from ghidra.app.decompiler import DecompInterface
decomp = DecompInterface()
decomp.openProgram(currentProgram)
for func in currentProgram.getFunctionManager().getFunctions(True):
    result = decomp.decompileFunction(func, 30, monitor)
    if result.decompiledFunction():
        code = result.getDecompiledFunction().getC()
        if "strcmp" in code or "memcmp" in code:
            print(f"Comparison in {func.getName()} at {func.getEntryPoint()}")
```

Ghidra's built-in emulator (`EmulatorHelper`) can decrypt runtime-constructed data statically:
```java
EmulatorHelper emu = new EmulatorHelper(currentProgram);
emu.writeRegister("RSP", 0x2fff0000);
emu.writeMemory(dataAddress, encryptedBytes);
emu.setBreakpoint(returnAddress);
emu.run(functionEntryAddress);
byte[] decrypted = emu.readMemory(outputAddress, length);
```

For .NET, use Ghidra's Sleigh-based decompilation or pass to dnSpy/ILSpy for better results. For Go binaries, install the golang-loader-plugin to parse Go type metadata and recover string references.

### IDA Pro

Hex-Rays decompiler is the gold standard. Use IDAPython for automation. For decision-tree obfuscation (200+ auto-generated functions), script extraction of comparison constants:
```python
import idc, idaapi
for seg_ea in Segments():
    for func_ea in Functions(seg_ea, seg_end):
        name = idc.get_func_name(func_ea)
        if name.startswith('f') and name[1:].isdigit():
            # Check for CMP instruction, extract operand
```

Use deobfuscation plugins: D-810 for pattern-based MBA simplification and opaque predicate removal, GOOMBA for Ghidra P-Code-level obfuscation matching.

### radare2 / Rizin

```bash
r2 -d ./binary
aaa             # Analyze all
afl             # List functions
pdf @ main      # Print disassembly of main
db 0x401234     # Set breakpoint
```

For custom VM tracing, use radare2's panel mode to pin program counter, opcode, stack, and heap simultaneously. Use `e io.cache=true` for non-destructive patching during analysis. Rizin/Cutter provides Ghidra decompiler integration via `r2ghidra` plugin.

### Binary Ninja

Lightweight alternative to Ghidra and IDA. Python API supports headless analysis and patching:
```python
import binaryninja
bv = binaryninja.open_view("binary")
for func in bv.functions:
    print(func.name, hex(func.start))
    print(func.hlil)  # High-Level IL for analysis
```

Patch via API:
```python
bv.write(0x401234, b"\x90" * 5)   # NOP 5 bytes
bv.write(0x401234, b"\x74")       # JNZ -> JZ
bv.write(0x401234, b"\xb8\x01\x00\x00\x00\xc3")  # mov eax,1; ret
bv.save("patched")
```

### LIEF for Binary Modification

Cross-format (ELF, PE, Mach-O) binary parsing and patching without disassembler:
```python
import lief
binary = lief.parse("binary")
section = lief.ELF.Section(".patch")
section.content = list(b"\xcc" * 0x100)
section.flags = lief.ELF.SECTION_FLAGS.EXECINSTR | lief.ELF.SECTION_FLAGS.ALLOC
binary.add(section)
binary.header.entrypoint = 0x401000
binary.patch_pltgot("strcmp", 0x401000)
binary.write("patched")
```

### RetDec (Retargetable Decompiler)

LLVM-based decompiler supporting x86, ARM, MIPS, PowerPC, PIC32. Free and open-source:
```bash
retdec-decompiler binary
retdec-decompiler --select-ranges 0x401000-0x401100 binary
```

Outputs compilable C decompilation. Good for architectures where Ghidra/IDA struggle.

### LLVM IR Analysis

When the challenge provides LLVM IR instead of a compiled binary:
```bash
llc task.ll --x86-asm-syntax=intel  # Convert to assembly
gcc -c task.s -o file.o
```

### Custom VM Bytecode Lifting

For complex custom VMs, transpile bytecode to LLVM IR and let `opt -O3` simplify:
```
Pipeline: VM bytecode -> custom disassembler -> LLVM IR -> opt -O3 -> decompile
```

The optimization passes (inlining, constant folding, dead code elimination) dramatically reduce instruction count, revealing the underlying algorithm.

### Symbol / Section / String Extraction

```bash
readelf -S binary              # Sections
readelf -s binary              # Symbols (if not stripped)
objdump -d binary              # Full disassembly
objdump -M intel -d binary     # Intel syntax
strings binary | grep -i flag  # Quick win
rabin2 -z binary               # radare2 string listing
```

### Cross-Reference with dogbolt.org

Upload binary to dogbolt.org to compare outputs from multiple decompilers (Hex-Rays, Ghidra, Binary Ninja, angr, RetDec, Snowman, Reko) side-by-side. Cross-referencing catches decompiler bugs and clarifies ambiguous structures.

## Bypass
For statically-linked/stripped ELF, run `nm -n binary` to find main (typically after `__libc_csu_init`). For Go binaries, use GoReSym to recover function names from embedded runtime metadata even when stripped. For section-header-corrupted ELF, patch `e_shoff` to 0 at offset 40 for Ghidra/IDA compatibility. For execute-only binaries that cannot be read, use `LD_PRELOAD` + `/proc/self/mem` to dump mapped memory at runtime.

## Verification
Extract expected comparison constants from `.rodata` or immediate operands. Reconstruct the algorithm inverse (transpiled or manual). Verify by running through the decompiled logic with test inputs. Cross-check against dogbolt.org output if Ghidra and IDA produce different decompilations.

## Pitfalls
Decompilers often get x86-64 sign extension wrong -- always verify `movsx`/`cdqe` behavior against raw assembly. Loop variables may update before or after use in assembly (decompilers sometimes reorder incorrectly). Go strings are `{ptr, len}` pairs, not null-terminated -- Ghidra without the golang-loader plugin will miss them. .NET NativeAOT and Kotlin/Native look like C++ in decompilation but have different object layouts. Single-byte XOR sweep (all 256 keys) should be tried before assuming a custom encryption algorithm.
