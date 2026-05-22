---
name: reverse-engineering
description: Reverse engineering techniques — static and dynamic analysis, anti-analysis countermeasures, language and platform-specific patterns. Use when the target is a compiled binary, obfuscated code, firmware image, mobile app (APK/IPA), WebAssembly module, or bytecode.
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, Ghidra/IDA/radare2, and debugging tools.
allowed-tools: Bash Read Write Edit Glob Grep WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "<binary-path or platform>"
---

# Reverse Engineering

## Triage

```bash
file binary
strings binary | head -100
xxd binary | head -20
binwalk -e binary      # embedded files
readelf -h binary       # architecture
objdump -d binary | head -50  # disassembly preview
```

## Document Map

| Task | Document |
|------|----------|
| Disassembly, decompiler, symbol recovery, signature matching | [Static Analysis](../../03-reverse-engineering/static-analysis.md) |
| Debugger, tracing, hooking, emulation, symbolic execution | [Dynamic Analysis](../../03-reverse-engineering/dynamic-analysis.md) |
| Anti-debug, anti-VM, packing, obfuscation, anti-disassembly | [Anti-Analysis](../../03-reverse-engineering/anti-analysis.md) |
| Go, Rust, Swift, Kotlin, Haskell, C++ patterns; APK, iOS, WASM, .NET, Unity, embedded | [Languages & Platforms](../../03-reverse-engineering/languages-platforms.md) |
| Tool reference — Ghidra, IDA, radare2, Binary Ninja, Frida, angr, Unicorn | [Tools](../../03-reverse-engineering/tools.md) |

## Quick Start by Platform

| Platform | Key Tools | First Step |
|----------|-----------|------------|
| ELF x86-64 | Ghidra + GDB | `checksec`, review decompiled main |
| Windows PE | IDA + x64dbg | Check sections, imports, TLS callbacks |
| Android APK | Jadx + Frida | Decompile to Java, hook with Frida |
| iOS IPA | Hopper + Frida | Check binary encryption, decrypted with frida-ios-dump |
| .NET | dnSpy / ILSpy | Open in dnSpy, check for obfuscation |
| WASM | wasm-decompile + Chrome DevTools | `wasm-decompile module.wasm` |
| Firmware | binwalk + QEMU | Extract filesystem, emulate if ARM/MIPS |
| Python .pyc | pycdc / decompyle3 | Decompile bytecode to source |
