---
name: forensics
description: Forensic analysis techniques — disk, memory, network, steganography, side-channel analysis. Use when given a disk image (.dd, .E01, .raw), memory dump (.vmem, .raw), packet capture (.pcap, .pcapng), image/audio file with hidden data, or side-channel trace.
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, sleuthkit, volatility3, tshark, and stego tools.
allowed-tools: Bash Read Write Edit Glob Grep WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "<evidence-file>"
---

# Forensics Analysis

## File Type Triage

```bash
file evidence
strings evidence | grep -iE '(flag|pass|key|secret)' | head -20
xxd evidence | head -5
```

## Document Map

| Evidence Type | Document |
|---------------|----------|
| Disk image, filesystem, deleted files, RAID, LUKS, partitions | [Disk Analysis](05-forensics/disk/index.md) |
| Memory dump, process list, credentials, injected code | [Memory Analysis](05-forensics/memory/index.md) |
| PCAP, TLS, DNS, covert channels, protocol analysis | [Network Forensics](05-forensics/network/index.md) |
| Image, audio, video with hidden data, LSB, spectrogram | [Steganography](05-forensics/steganography/index.md) |
| Power trace, timing data, EM emanations, keyboard acoustics | [Side-Channel](05-forensics/side-channel/index.md) |

## Fast Path by File Extension

| Extension | Category | First Commands |
|-----------|----------|----------------|
| `.dd`, `.raw`, `.E01`, `.img` | Disk | `mmls`, `fsstat`, `fls -r`, `icat` |
| `.vmem`, `.dmp`, `.core` | Memory | `volatility3 -f image windows.info` |
| `.pcap`, `.pcapng` | Network | `tshark -r capture`, `capinfos capture` |
| `.png`, `.jpg`, `.bmp`, `.wav` | Stego | `zsteg`, `steghide`, `exiftool`, `binwalk -e` |
| `.csv` (logic analyzer) | Side-Channel | Parse and plot values over time |

## Stego Checklist

```bash
strings image.png | grep -i flag
exiftool image.png | grep -iE '(comment|description|artist|copyright)'
zsteg image.png
steghide extract -sf image.jpg -p ""
binwalk -e image.png
# Check for appended data after EOF
xxd image.png | tail -20
# Spectrogram for audio
sox audio.wav -n spectrogram -o spec.png
```
