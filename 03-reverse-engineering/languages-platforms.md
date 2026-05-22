# Languages and Platforms

## Trigger
When the binary is compiled from a high-level language (Go, Rust, Swift, Kotlin, Haskell, D, C++) or targets a specific platform (Android, iOS, WebAssembly, .NET, Unity, UEFI, embedded/IoT, kernel modules, game engines, hardware/HDL). Also for esoteric language challenges (Brainfuck, FRACTRAN, Make Turing machines, OPAL).

## Attack Surface
Language-specific constructs: Go runtime metadata and goroutine concurrency, Rust ownership/borrow and panic messages, Swift protocol witness tables and value types, Kotlin coroutine state machines, Haskell STG closures and lazy evaluation, C++ vtables and RTTI. Platform-specific: APK/DEX bytecode, Mach-O and dyld/lldb, PE32+ for UEFI, .NET IL/CLR, WASM linear memory, firmware filesystems, kernel ioctl interfaces, game engine scripting.

## Decision Tree
Identify language (file/strings/checksec) -> apply language-specific symbol recovery -> understand memory layout -> locate main entry and key functions -> match decompilation patterns -> extract algorithm.

Run `strings binary | grep -E "go\.buildid|runtime\.gopanic"` for Go; `core::panicking` and `/rustc/` for Rust; `swift` and `__swift5_*` sections for Swift; `kotlin.Metadata` for Kotlin/JVM; `libHS*` for Haskell. Check `.rustc` section for Rust ELF binaries.

## Techniques

### Go Binary Reversing

**Recognition:** Very large binary (2MB+ for trivial programs), `go.buildid`, `runtime.*` symbols, `main.main` as entry (not `main`).

**Symbol recovery with GoReSym:**
```bash
./GoReSym -d binary > symbols.json
python3 -c "
import json
with open('symbols.json') as f:
    data = json.load(f)
for fn in data.get('UserFunctions', []):
    print(f'{fn[\"Start\"]:#x}  {fn[\"FullName\"]}')
"
```

**Go memory layout:**
```
String:  {char *ptr, int64 len}        -- 16 bytes, NOT null-terminated
Slice:   {void *ptr, int64 len, int64 cap} -- 24 bytes
Interface: {void *type, void *data}      -- 16 bytes
```

In Ghidra, a function taking `(ptr, int64)` is likely receiving a Go string. Three fields `(ptr, int64, int64)` is a slice.

**Goroutine analysis:** Look for `runtime.newproc` for spawns, `runtime.chansend1`/`runtime.chanrecv1` for channel operations. Use GDB with Go runtime support:
```bash
gdb ./binary
(gdb) source /usr/local/go/src/runtime/runtime-gdb.py
(gdb) info goroutines
```

**Common stdlib patterns:** `crypto/aes`, `crypto/sha256`, `encoding/hex`, `encoding/base64` for crypto operations. `fmt.Sprintf` with format strings in `.rodata`. `runtime.concatstrings` for string concatenation.

**Go embed.FS (Go 1.16+):** Embedded files appear as raw data in the binary. Search for known file signatures (PK for zip, PNG header).

### Rust Binary Reversing

**Recognition:** `core::panicking::panic` strings, `.rustc` ELF section, `/rustc/<commit>/library/` paths, `_ZN` mangled symbols (Itanium ABI, same as C++).

**Symbol demangling:**
```bash
cargo install rustfilt
nm binary | rustfilt | grep "main"
```

**Common Rust types in decompilation:**
```
Option<T>:  {discriminant (0=None, 1=Some), T value}
Result<T,E>: {discriminant (0=Ok, 1=Err), union{ok_val, err_val}}
Vec<T>:     {void *ptr, uint64 cap, uint64 len}  -- same as Go slice
String:     {void *ptr, uint64 cap, uint64 len}  -- 24 bytes, heap-allocated
&str:       {void *ptr, uint64 len}              -- 16 bytes, borrowed
```

**Panic strings are goldmines:**
```bash
strings binary | grep "panicked at"
strings binary | grep "called .unwrap().. on"
```
These often contain file paths, line numbers, and variable names even in release builds.

**Rust serde_json schema recovery:** Disassemble serde `Visitor` implementations to recover expected JSON schema from deserializer code. Look for `visit_str`, `visit_u64`, `visit_seq` method names to infer types. Field names in visitor order may reveal the flag.

### Swift Binary Reversing

**Recognition:** `__swift5_*` sections in Mach-O, `swift_*` runtime symbols, `s` prefix in mangled names.

**Demangling:**
```bash
swift demangle 's14MyApp0A8ClassC10checkInput6resultSbSS_tF'
# -> MyApp.MyAppClass.checkInput(result: String) -> Bool
```

**Key runtime functions:** `swift_allocObject` (heap allocation), `swift_release` (reference count decrement), `swift_once` (lazy init). String layout: small strings (<=15 bytes) inline in 16-byte tagged pointer; large strings are heap-allocated.

### Kotlin / JVM Binary Reversing

**JVM bytecode:** Use `jadx` for best decompilation:
```bash
jadx classes.dex
```

**Kotlin coroutines:** Compile to state machines inside `invokeSuspend`. Each suspend point becomes a `switch` case (label 0, 1, 2, ...). Follow the state machine to understand async flow.

**Kotlin/Native:** LLVM backend produces platform binaries without JVM metadata. No reflection information, looks like C++ in disassembly. Recognizable by `konan`, `kotlin.native` strings.

### Haskell Binary Reversing

GHC-compiled binaries use the STG (Spineless Tagless G-machine) execution model. Extremely difficult to decompile due to lazy evaluation, closures, and thunks.

**Recognition:** `libHSbase-*` shared libraries, `hs_main` entry point, Z-encoded symbols (e.g., `MainZCmain` for `Main.main`).

**Closure structure:** First qword points to info table/code. Info table precedes code pointer with metadata (closure type, layout).

**Tools:** `hsdecomp` recovers closure structure and pattern matching into pseudo-Haskell. For recursive string constructions with exponential growth (`f(n) = s1 + f(n-1) + s2 + f(n-1) + s3`), compute segment sizes with memoization:
```python
from functools import lru_cache
@lru_cache(maxsize=None)
def fsize(n):
    if n == 0: return len(s0)
    return len(s1) + fsize(n-1) + len(s2) + fsize(n-1) + len(s3)

def char_at(n, offset):
    # Binary search through segments without materializing the full string
```
Direct evaluation would be O(2^n). Size memoization makes it linear.

### C++ Binary Reversing

**vtable reconstruction:** First 8 bytes of object point to vtable. Entries: `[typeinfo_ptr, destructor, method1, method2, ...]`. Polymorphic dispatch: `mov rax, [rdi]; call [rax + 0x18]`.

**RTTI:** If not stripped, RTTI reveals class hierarchy:
```bash
strings binary | grep -E "^[0-9]+[A-Z]"
c++filt _ZTI7MyClass  # -> typeinfo for MyClass
```

**STL patterns:**
```
std::string: SSO (<=15 chars inline), layout: {char* ptr, size_t size, union{size_t cap, char[16]}}
std::vector: {T* begin, T* end, T* capacity_end}
```

### Android APK Analysis

```bash
apktool d app.apk -o decoded/
jadx app.apk                    # Java decompilation
unzip app.apk -d extracted/     # Simple extraction
```

**Key locations:** `res/values/strings.xml`, `AndroidManifest.xml`, `classes.dex`, `assets/`, `lib/`.

**JNI RegisterNatives obfuscation:** If `JNI_OnLoad` calls `RegisterNatives`, the native handler names are hidden (no `Java_com_pkg_Class_method` symbol). Trace `JNI_OnLoad` -> `RegisterNatives` -> `fnPtr` array. Prefer `x86_64` `.so` from lib for best Ghidra decompilation.

**Native .so loading bypass:** Create new Android project with matching package/class/method, load original .so, call native method directly -- bypasses all Java-level validation (PIN, root detection, random checks).

**DEX runtime bytecode patching:** Native library patches DEX in memory via `/proc/self/maps` + `mprotect` + XOR. Extract XOR key and offsets from the .so to reconstruct the runtime DEX.

### iOS / macOS Analysis

```bash
# Mach-O binary analysis
otool -l binary                # Load commands
otool -L binary                # Linked dylibs
lipo -info universal_binary    # Fat binary arches
lipo binary -thin arm64 -out aarch64_binary

# Objective-C runtime
class-dump binary > classes.h  # Dump interfaces
# Selector strings in __objc_methname section

# Code signing
codesign -d --entitlements - binary
codesign --remove-signature binary  # For patching
codesign -f -s - binary            # Ad-hoc re-sign
```

**iOS app decryption (FairPlay DRM):** `cryptid = 1` in `LC_ENCRYPTION_INFO` means encrypted. Use frida-ios-dump or Clutch on jailbroken device.

### WASM Analysis

```bash
wasm2c checker.wasm -o checker.c   # Decompile to C
wasm2wat main.wasm -o main.wat     # Binary to text format
wat2wasm main.wat -o patched.wasm  # Text to binary (for patching)
```

WASM patching for game challenges: flip comparisons (`i64.lt_s` -> `i64.gt_s`), change constants in WAT text, recompile.

### .NET Analysis

**Tools:** dnSpy (debugging + decompilation), ILSpy (decompilation), dotPeek.

**ConfuserEx unpacking:** Break on `<Module>.cctor` constructor in dnSpy, wait for runtime decryption, right-click -> Save Module. Then run `de4dot` for symbol cleanup.

**NativeAOT:** Look for `System.Private.CoreLib` strings. Type metadata present but restructured. Search for length-prefixed UTF-16 patterns.

### Unity (IL2CPP) Analysis

```bash
Il2CppDumper libil2cpp.so global-metadata.dat out/
grep -r "https://" out/    # Find hardcoded endpoints
```

If Il2CppDumper fails, `global-metadata.dat` may be encrypted. Trace the metadata loading path in the native binary for custom decryption. Key derivation: `key = SHA256(companyName + "\n" + productName)`.

### Embedded / IoT Firmware

```bash
binwalk -Me firmware.bin              # Recursive extraction
unsquashfs -d output/ root.sqfs       # SquashFS
jefferson -d output/ jffs2.img        # JFFS2
ubireader_extract_images firmware.ubi  # UBI/UBIFS
dtc -I dtb -O dts device_tree.dtb     # Device tree
```

**Cross-architecture emulation:**
```bash
qemu-arm -L /usr/arm-linux-gnueabihf/ ./arm_binary
qemu-arm -g 1234 ./arm_binary  # GDB server
qemu-mips -L /usr/mips-linux-gnu/ ./mips_binary
```

### Brainfuck / Esolangs

BF input validation programs follow patterns: `,` (read char) followed by `+` operations whose count equals expected ASCII value. Extract by counting increments per segment:
```python
segments = bf_code.split(',')
for seg in segments[1:]:
    plus_count = sum(1 for ch in seg if ch == '+')
    if plus_count > 0: expected.append(chr(plus_count % 256))
```

BF side-channel: correct characters cause more `,` (read) operations because the program advances to validate the next position. Count reads per candidate byte.

### Other Platforms

**FFmpeg custom filter:** Look for `avcodec_register`, `AVCodec` structs. Command line reveals filter name. Decompile the filter's init/decode callbacks.

**UEFI:** Extract firmware with `7z x firmware.bin`, identify PE32+ files with `file`, load in Ghidra/IDA as standard PE.

**Linux kernel modules (.ko):** Find ioctl handler in `file_operations` struct. Trace `copy_from_user`/`copy_to_user`. Debug with QEMU+GDB (`-s -S`).

**Game Boy ROM (Z80/SM83):** Use `bgb` emulator debugger. Comparison instructions: `LD A, [HL]`, `AND [HL]`, `CP N`. Expected byte visible at `(HL)` address.

**Verilog/HDL:** Analyze `always @(posedge clk)` blocks and `case` statements for hidden conditions gated on shift register history. Build timing model for each action type, work backward from required history values.

**ESP32/Xtensa:** Use radare2 with ESP-IDF ROM linker script (`esp32.rom.ld`) for symbol resolution. Cross-reference with public ESP-IDF example code.

## Verification
Confirm language identification by extracting version strings (Go version, Rust compiler commit, Swift version, .NET framework). Verify recovered function names by checking cross-references and calling convention alignment. Test decompiled code against known input/output pairs.

## Bypass

| Language | Common Anti-RE Pattern | Countermeasure |
|----------|----------------------|----------------|
| Go | Static linking, large binaries | Symbol recovery via `go_parser`, `IDAGolangHelper` |
| Rust | Name mangling, monomorphization | `rust-demangle`, pattern recognition |
| .NET | Obfuscation (ConfuserEx, .NET Reactor) | `de4dot`, `dnSpy` with managed debugging |

## Pitfalls
Go strings are NOT null-terminated -- Ghidra without golang-loader plugin misses them. Rust monomorphization creates many similar-looking functions. Kotlin/Native lacks JVM metadata, making it C++-like in decompilation. Haskell STG closures make standard disassembly nearly useless -- use `hsdecomp`. Brainfuck programs with loop-based multiplication (compiled from BF-it) need nested operation counting. Unity IL2CPP metadata may be encrypted -- not always directly dumpable.
