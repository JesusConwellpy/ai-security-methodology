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
# Mimikatz plugin
vol.py --plugins=./plugin/ -f dump.vmem --profile=Win7SP1x64 mimikatz

# Hashdump from SAM registry
vol.py -f dump.vmem --profile=Win7SP1x64 hivelist
vol.py -f dump.vmem --profile=Win7SP1x64 hashdump -y SYSTEM_off -s SAM_off

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
grep -c '\x19\xAB\x5E\xDC\x02\xF0\x97\xD5' corefile
# 3. Read 48 bytes before session ID match as master_key
# 4. Create Wireshark pre-master-secret log:
# RSA Session-ID:<hex_id> Master-Key:<hex_key>
```

### Linux Ransomware Key Recovery from Memory

When ransomware encrypts files and the AES key resides in memory:

```bash
# Check Volatility first
vol -f memdump.raw linux.pslist
vol -f memdump.raw linux.proc.Maps

# If Volatility fails, raw candidate scanning
strings -a memdump.raw | grep "/home/.*/enc_key.bin"

# Test 32-byte candidates against known file magic
python3 << 'EOF'
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
    if hasattr(obj, 'func_code'):
        print(f"\n=== {name} ===")
        uncompyle6.main.uncompyle(sys.version_info[0] + sys.version_info[1]/10.0,
                                   obj.func_code, sys.stdout)
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

## Bypass

When standard Volatility plugins fail: use GIMP raw import to find framebuffer data visually, brute-force raw string scanning with anchored candidate search near known strings, extract process memory manually from known offsets, try alternate profiles/symbols, use `strings -a -n 6` on raw dump for all text, search for known magic bytes patterns, reconstruct encryption keys from raw memory fragments. When Linux plugins return empty due to KASLR mismatch, fall back to raw candidate scanning with magic-byte validation for key recovery.

## Verification

Confirm by: flag extracted from process memory, credential hashes crack successfully, encryption key decrypts target files, TLS session key enables PCAP decryption, recovered string matches expected pattern, process list reveals malicious activity, network connections show C2 communication.

## Pitfalls

Running Volatility 2 plugins on Volatility 3 (e.g., `mftparser` is Vol2 only; use `mftscan` in Vol3). Forgetting to use `mimikatz` instead of `hashdump` for plaintext credentials. Assuming a single profile works for all memory dumps. Not checking process memory dumps (use `memdump --pid`). Overlooking clipboard content. Not verifying that extracted processes are legitimate (psxview compares multiple process lists). Assuming strings output covers all data (some regions use UTF-16LE). Ignoring environment variables in process memory. Not checking for pagefile/swap artifacts. Forgetting that memory dumps may contain base64-encoded payloads in transit.
