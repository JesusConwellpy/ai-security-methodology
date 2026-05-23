# Memory Forensics

## Trigger

Load when presented with: memory dump files (.raw, .dmp, .vmem, .mem, .elf, .core), hibernation files, VMware snapshot files (.vmss, .vmsn), crash dumps (minidump .dmp, full memory dump), process dumps, or challenges involving running processes, network connections, encryption keys in memory, malware analysis, or credential extraction.

## Attack Surface

Evidence characteristics: OS type and version (Windows, Linux, macOS) determines Volatility profile/plugin selection, acquisition method (raw memory, vmss2core conversion, coredump, minidump) affects completeness, pagefile/swap may contain additional evidence, hibernation files contain compressed memory state, KASLR/address randomization may prevent symbol loading, architecture (32-bit vs 64-bit) affects address space layout.

## Decision Tree

1. Identify dump type: `file memory.dmp`
2. Run Volatility 3: `vol3 -f memory.dmp windows.info` or `vol3 -f memory.dmp linux.banner`
3. List processes: `vol3 -f memory.dmp windows.pslist`
4. Check command lines: `vol3 -f memory.dmp windows.cmdline`
5. Scan network connections: `vol3 -f memory.dmp windows.netscan`
6. Scan files in memory: `vol3 -f memory.dmp windows.filescan`
7. Dump suspicious files: `vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>`
8. Check clipboard: `vol3 -f memory.dmp windows.clipboard`
9. String search: `strings -a -n 6 memory.dmp | grep -i "flag\|password\|key"`
10. If Volatility fails: GIMP raw visual inspection, manual string carving
11. If macOS dump: `vol3 -f memory.dmp macos.check_mac_version`, check Keychain via `macos.keychaindump`, parse Unified Logs with `macos.unifiedlogs`
12. If hibernation file (hiberfil.sys): decompress with `hibr2bin -o memory.dmp hiberfil.sys`, then run Volatility as raw dump
13. If crash dump: use `vol3 -f memory.dmp windows.crashinfo` to identify dump type, extract targeted process memory

## Techniques

### Volatility 3 Core Plugins

```bash
# System info and profile
vol3 -f memory.dmp windows.info

# Process listing
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.pstree
vol3 -f memory.dmp windows.cmdline

# Network artifacts
vol3 -f memory.dmp windows.netscan

# File scanning and extraction
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr 0x...

# MFT scan (NTFS file metadata in memory)
vol3 -f memory.dmp windows.mftscan | grep flag

# Registry extraction
vol3 -f memory.dmp windows.registry.hivelist

# Clipboard (copy-paste secrets)
vol3 -f memory.dmp windows.clipboard

# Process memory dump
vol3 -f memory.dmp windows.memdump --pid 3720 -D out/
```

### Memory String Carving

```bash
# Fast flag search
strings -a memory.dmp | grep -iE "flag|ctf|key|secret|password"

# Extended search with minimum length
strings -a -n 6 memdump.bin | grep -E "FLAG|SSH_CLIENT|SESSION_KEY"

# Search environment variables
strings -a cold-workspace.dmp | grep -i "flag\|password\|key\|secret"

# Base64-encoded ZIP in transit (UEsD = base64 of PK\x03)
strings dump.raw | grep -o 'UEsD[A-Za-z0-9+/=]*'
```

### Windows Credential Recovery

```bash
# Mimikatz plugin (third-party plugin for Volatility 3)
vol3 -f dump.vmem windows.mimikatz --plugins ./plugin/

# Hashdump from SAM registry
vol3 -f dump.vmem windows.registry.hivelist
vol3 -f dump.vmem windows.hashdump --sys-offset <SYSTEM_offset> --sam-offset <SAM_offset>

# NTLM hash verification
python3 -c "
from Crypto.Hash import MD4
h = MD4.new()
h.update('password'.encode('utf-16-le'))
print(h.hexdigest())
"
```

### GIMP Raw Memory Visual Inspection

When Volatility profiles fail to match or plugins produce empty output, raw memory dumps may contain framebuffer pixel data. Open the .dmp file in GIMP as Raw Image Data with RGB format at 1920px width, then scroll through offsets. Previously displayed screenshots become visible when width matches the original display stride.

```python
# Automated scanning for framebuffer data
from PIL import Image
import numpy as np
with open('memory.dmp', 'rb') as f:
    data = f.read()
for width in [1920, 1366, 1280, 1024]:
    stride = width * 3
    for offset in range(0, len(data) - stride * 100, stride * 500):
        chunk = data[offset:offset + stride * 100]
        if len(chunk) == stride * 100:
            img = Image.frombytes('RGB', (width, 100), chunk)
            arr = np.array(img)
            if 10 < arr.mean() < 245 and arr.std() > 20:
                img.save(f'frame_{width}_{offset}.png')
```

### Coredump Analysis

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
(gdb) info proc mappings
```

### TLS Master Key Extraction from Coredump

When PCAP with HTTPS traffic and a server coredump are both available, extract the TLS master key from OpenSSL's in-memory session structure:

```bash
# 1. Find TLS Session ID from Wireshark handshake (ClientHello/ServerHello)
# 2. Search coredump for session ID bytes
grep -cP '\x19\xAB\x5E\xDC\x02\xF0\x97\xD5' corefile
# 3. Read 48 bytes before session ID match as master_key
# 4. Create Wireshark pre-master-secret log:
# RSA Session-ID:<hex_id> Master-Key:<hex_key>
```

### Linux Ransomware Key Recovery from Memory

When ransomware encrypts files and the AES key resides in memory:

```bash
# Check Volatility first
vol3 -f memdump.raw linux.pslist
vol3 -f memdump.raw linux.proc.Maps

# If Volatility fails, raw candidate scanning
strings -a memdump.raw | grep "/home/.*/enc_key.bin"

# Test 32-byte candidates against known file magic
python3 << 'EOF'
from Crypto.Cipher import AES
candidates = [...]  # extracted from memory near anchor strings
for key in candidates:
    for veg_file in encrypted_files:
        iv = veg_file[:16]
        ct = veg_file[16:]
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        pt = cipher.decrypt(ct)
        if pt[:4] in (b'\x89PNG', b'%PDF', b'PK\x03\x04'):
            print(f"Found key: {key.hex()}")
EOF
```

### PowerShell Ransomware Analysis

```bash
# Extract PowerShell script blocks from minidump
python power_dump.py powershell.DMP

# String search for encryption keys
strings powershell.DMP | grep -E '^[A-Za-z0-9]{24}$' | sort | head
```

### Python In-Memory Source Recovery

```bash
# Attach to running Python process
pyrasite-shell <PID>
# Inside pyrasite shell:
import sys, uncompyle6
for name, obj in globals().items():
    if hasattr(obj, '__code__'):       # Python 3: func_code was renamed to __code__
        print(f"\n=== {name} ===")
        uncompyle6.main.uncompyle(sys.version_info[0] + sys.version_info[1]/10.0,
                                   obj.__code__, sys.stdout)
print(globals())  # May contain flags, keys
```

### AES Key Schedule Detection

```bash
# Find AES keys in raw memory
aeskeyfind memory.elf
# Output: candidate AES-256 keys (64 hex chars each)

# Convert to binary key file
echo "deadbeef..." | xxd -r -p > master.key

# RSA key detection
rsakeyfind memory.elf
```

### macOS Memory Forensics

```bash
# Volatility 3 macOS profile detection
vol3 -f macmem.dmp macos.check_mac_version
vol3 -f macmem.dmp macos.list_sessions

# Process enumeration on macOS
vol3 -f macmem.dmp macos.pslist
vol3 -f macmem.dmp macos.pstasks
vol3 -f macmem.dmp macos.bash_env

# Code signing verification (flag unsigned processes)
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["vol3", "-f", "macmem.dmp", "macos.pslist", "--output=csv"])
for line in out.decode().strip().split('\n')[1:]:
    cols = line.split(',')
    if len(cols) >= 5:
        pid, name, path = cols[1], cols[2], cols[3]
        try:
            cs_out = subprocess.check_output(
                ["vol3", "-f", "macmem.dmp", "macos.check_code_signature",
                 "--pid", pid], stderr=subprocess.DEVNULL)
            if "unsigned" in cs_out.decode().lower():
                print(f"UNSIGNED: PID {pid} {name}")
        except:
            pass
EOF

# Keychain extraction from memory
vol3 -f macmem.dmp macos.keychaindump

# Search for binary plist data in memory (bplist00 magic)
python3 << 'EOF'
with open("macmem.dmp", "rb") as f:
    data = f.read()
pos = 0
count = 0
while True:
    idx = data.find(b"bplist00", pos)
    if idx < 0 or count >= 10:
        break
    plist_start = idx & ~0xFFF
    plist_data = data[plist_start:plist_start + 0x10000]
    with open(f"keychain_{count}.bplist", "wb") as out:
        out.write(plist_data)
    print(f"Extracted binary plist at offset {plist_start}")
    pos = idx + 1
    count += 1
EOF

# FSEvents extraction (file system event history)
vol3 -f macmem.dmp macos.fsevents
strings -a macmem.dmp | grep -E "/Users/.*/Documents/" | sort -u | head -20

# Unified Log extraction (macOS consolidated log)
vol3 -f macmem.dmp macos.unifiedlogs
vol3 -f macmem.dmp macos.unifiedlogs --level 3

# Parse specific log subsystems
vol3 -f macmem.dmp macos.unifiedlogs --subsystem com.apple.authd

# TCC database (Transparency, Consent, and Control) - app permissions
vol3 -f macmem.dmp macos.filescan | grep -i tcc
# Extract TCC.db from memory and query
# vol3 -f macmem.dmp macos.dumpfiles --virtaddr 0x...
# sqlite3 dumped_tcc.db "SELECT * FROM access;"

# Launchd plist extraction (persistence mechanisms)
vol3 -f macmem.dmp macos.filescan | grep -i "LaunchAgents\|LaunchDaemons"
# vol3 -f macmem.dmp macos.dumpfiles --physaddr 0x...

# Network connections on macOS
vol3 -f macmem.dmp macos.netstat
vol3 -f macmem.dmp macos.socket_handles
```

### Windows Hibernation File and Crash Dump Analysis

```bash
# Hibernation file decompression (hiberfil.sys)
# hiberfil.sys = compressed memory snapshot taken at sleep/hibernate
hibr2bin -o memory.dmp hiberfil.sys
# Alternative: use Hibr2Dmp
hibr2dmp -f hiberfil.sys -o memory.dmp

# Verify decompressed dump type
file memory.dmp
# Expected: "Windows 64-bit memory dump" or similar

# Analyze decompressed hibernation with Volatility
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.netscan

# Parse hibernation file header
python3 << 'EOF'
import struct
with open("hiberfil.sys", "rb") as f:
    header = f.read(4096)
signature = header[:4]
if signature == b"hibr":
    print("Hibernation file (pre-Win8)")
elif signature == b"\xDE\xAD\xBE\xEF":
    print("Hibernation file (Win8+)")
else:
    print(f"Unknown signature: {signature.hex()}")
page_size = struct.unpack_from("<I", header, 0x08)[0]
total_pages = struct.unpack_from("<I", header, 0x10)[0]
compressed_size = struct.unpack_from("<I", header, 0x18)[0]
print(f"Page size: {page_size}, Total pages: {total_pages}, Compressed: {compressed_size}")
EOF

# Manual page descriptor scan for residual data
python3 << 'EOF'
import struct
with open("hiberfil.sys", "rb") as f:
    data = f.read()
page_size = 4096
desc_count = len(data) // (page_size + 16)
for i in range(min(desc_count, 100)):
    desc_off = i * (page_size + 16) + 0x1000
    orig = struct.unpack_from("<I", data, desc_off)[0]
    comp = struct.unpack_from("<I", data, desc_off + 4)[0]
    flags = struct.unpack_from("<I", data, desc_off + 12)[0]
    if flags != 0:
        print(f"Page {i}: original={orig}, compressed={comp}, flags={flags:#x}")
        if 0 < orig <= page_size:
            page_data = data[desc_off + 16:desc_off + 16 + comp]
            if b"CTF{" in page_data or b"flag" in page_data:
                print(f"  *** FLAG in page {i}")
EOF

# Crash dump type identification
vol3 -f crash.dmp windows.crashinfo
vol3 -f crash.dmp windows.info

# Extract specific process from crash dump
vol3 -f crash.dmp windows.pslist
vol3 -f crash.dmp windows.memdump --pid <PID> -D extracted/

# Minidump header parsing
python3 << 'EOF'
import struct
with open("minidump.dmp", "rb") as f:
    header = f.read(32)
if header[:4] == b"MDMP":
    version = struct.unpack_from("<I", header, 4)[0]
    streams = struct.unpack_from("<I", header, 8)[0]
    stream_dir_rva = struct.unpack_from("<I", header, 12)[0]
    print(f"Minidump v{version}, {streams} streams")
    f.seek(stream_dir_rva)
    for s in range(streams):
        data = f.read(12)  # ONE read per iteration
        if len(data) < 12:
            break
        stype = struct.unpack_from("<I", data, 0)[0]
        ssize = struct.unpack_from("<I", data, 4)[0]
        srva = struct.unpack_from("<I", data, 8)[0]
        type_names = {0: "Unused", 2: "ThreadList", 3: "ModuleList",
                      4: "MemoryList", 5: "Exception", 6: "SystemInfo"}
        print(f"  Stream {s}: {type_names.get(stype, 'Unknown')}, size={ssize}")
        f.seek(12 * (s + 1) + stream_dir_rva)
EOF

# Key extraction targets in hibernation files
# Network connection state at time of hibernation
vol3 -f memory.dmp windows.netscan
# Registry hives (SYSTEM, SAM, SECURITY, SOFTWARE)
vol3 -f memory.dmp windows.registry.hivelist
vol3 -f memory.dmp windows.hashdump --sys-offset <offset> --sam-offset <offset>
# Clipboard content (copy-paste at hibernation)
vol3 -f memory.dmp windows.clipboard
# Open file handles
vol3 -f memory.dmp windows.handles
# Command history
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.cmdhistory
# Registry key inspection for system info
vol3 -f memory.dmp windows.registry.printkey \
  --key "ControlSet001\\Control\\ComputerName\\ComputerName"
```

## Bypass

When standard Volatility plugins fail: use GIMP raw import to find framebuffer data visually, brute-force raw string scanning with anchored candidate search near known strings, extract process memory manually from known offsets, try alternate profiles/symbols, use `strings -a -n 6` on raw dump for all text, search for known magic bytes patterns, reconstruct encryption keys from raw memory fragments. When Linux plugins return empty due to KASLR mismatch, fall back to raw candidate scanning with magic-byte validation for key recovery.

## Verification

Confirm by: flag extracted from process memory, credential hashes crack successfully, encryption key decrypts target files, TLS session key enables PCAP decryption, recovered string matches expected pattern, process list reveals malicious activity, network connections show C2 communication.

## Pitfalls

Running Volatility 2 plugins on Volatility 3 (e.g., `mftparser` is Vol2 only; use `mftscan` in Vol3). Forgetting to use `mimikatz` instead of `hashdump` for plaintext credentials. Assuming a single profile works for all memory dumps. Not checking process memory dumps (use `memdump --pid`). Overlooking clipboard content. Not verifying that extracted processes are legitimate (psxview compares multiple process lists). Assuming strings output covers all data (some regions use UTF-16LE). Ignoring environment variables in process memory. Not checking for pagefile/swap artifacts. Forgetting that memory dumps may contain base64-encoded payloads in transit.
