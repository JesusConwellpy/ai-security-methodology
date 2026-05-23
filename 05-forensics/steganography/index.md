# Steganography

## Trigger

Load when presented with: image files (.png, .jpg, .bmp, .gif, .webp), audio files (.wav, .mp3, .flac, .ogg), video files (.mp4, .avi, .mkv, .mjpeg), document files (.pdf, .docx, .svg, .xlsx), archive files with hidden data, text files with invisible characters, terminal output captures, or challenges involving hidden messages, data obfuscation, covert communication, or multi-layer encoding.

## Attack Surface

Evidence characteristics: file format structure determines hiding spots (metadata chunks, padding bytes, unused fields, compression artifacts), pixel format affects LSB capacity, encoding redundancy (JPEG DCT, PNG filters, GIF palette) creates covert channels, metadata fields (EXIF, comments, XMP) can carry arbitrary data, file format parsers skip unrecognized chunks, multi-frame formats (GIF, APNG, video) hide data across temporal dimensions.

## Decision Tree

1. Initial scan: `file`, `exiftool`, `binwalk`, `strings -a`, `hexdump -C`
2. LSB analysis: `zsteg image.png`, `stegsolve`, `python3 stego-lsb`
3. Known tool extraction: `steghide extract -sf image.jpg`
4. Audio spectrogram: `sox audio.wav -n spectrogram -o spec.png`
5. Metadata check: `exiftool -a file` for all metadata fields
6. Post-trailer check: bytes after `%%EOF` (PDF), `IEND` (PNG), `FFD9` (JPEG)
7. Multi-frame: extract all frames, diff consecutive, check palettes
8. File-within-file: `binwalk --dd=".*"` to carve embedded documents
9. If standard tools fail: try custom bitplane extraction, non-standard LSB positions, frequency domain analysis, whitespace/zero-width character encoding
10. Check for encryption layer (XOR, ROT, base64) after extraction
11. Examine video containers: `mp4info file.mp4`, check for custom UUID atoms, extra tracks, injected data between atoms
12. Analyze network captures: `tshark -r capture.pcap -T fields -e ip.id`, check for anomalies in TCP ISN, HTTP headers, DNS queries, TLS handshake fields

## Techniques

### Image Steganography

```bash
# Quick scan
zsteg image.png                   # PNG/BMP LSB analysis
zsteg -a image.png                # All planes/bit depths
stegsolve                         # GUI for visual plane analysis
steghide extract -sf image.jpg    # Known tool
stegseek image.jpg rockyou.txt    # Faster brute-force than stegcracker

# Metadata
exiftool -a image.jpg
strings -a image.jpg | grep -i "flag\|comment\|author"

# Binwalk for embedded files
binwalk --dd=".*" image.png
```

### LSB and Bitplane Extraction

```python
# Standard single-bit LSB (all pixels)
from PIL import Image
img = Image.open('image.png')
bits = ''.join(str(pixel[0] & 1) for pixel in img.getdata())
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))

# Cross-channel multi-bit LSB (different bit per channel)
img = Image.open("challenge.png")
pixels = img.load()
bits = []
for y in range(img.height):
    for x in range(img.width):
        r, g, b = pixels[x, y][:3]
        bits.append((r >> 0) & 1)  # Red: bit 0
        bits.append((g >> 1) & 1)  # Green: bit 1
        bits.append((b >> 2) & 1)  # Blue: bit 2
data = bytearray()
for i in range(0, len(bits) - 7, 8):
    byte = sum(bits[i+j] << (7-j) for j in range(8))
    data.append(byte)
print(data.decode('ascii', errors='ignore'))

# BMP bitplane extraction (check bits 0, 1, 2 across RGB)
import numpy as np
pixels = np.array(Image.open('challenge.bmp'))
for ch_idx, ch_name in enumerate(['R', 'G', 'B']):
    for bit in range(3):
        channel = pixels[:, :, ch_idx]
        bit_plane = ((channel >> bit) & 1) * 255
        Image.fromarray(bit_plane.astype(np.uint8)).save(f'bit_{ch_name}_{bit}.png')

# Conditional LSB - only near-black pixels carry data
bits = ''
for pixel in img.getdata():
    r, g, b = pixel[0], pixel[1], pixel[2]
    if not (r <= 1 and g <= 1 and b <= 1):
        continue
    bits += str(r & 1) + str(g & 1) + str(b & 1)

# RGB parity steganography (even/odd sum)
out = Image.new('1', img.size)
for x in range(img.width):
    for y in range(img.height):
        r, g, b = img.getpixel((x, y))[:3]
        out.putpixel((x, y), (r + g + b) % 2)
out.save('hidden.png')
```

### PNG Manipulation

```bash
# Fix corrupt PNG magic and lowercase chunks
printf '\x89PNG\r\n\x1a\n' | dd of=broken.png conv=notrunc bs=1 count=8
```

```python
with open('broken.png', 'rb') as f:
    d = bytearray(f.read())
d = d.replace(b'idat', b'IDAT').replace(b'iend', b'IEND')
open('fixed.png', 'wb').write(d)

# PNG hidden height (brute-force from IHDR CRC)
import struct, zlib
with open('image.png', 'rb') as f:
    data = bytearray(f.read())
ihdr_start = 12  # skip sig(8) + chunk_len(4)
stored_crc = struct.unpack('>I', data[ihdr_start+17:ihdr_start+21])[0]
for h in range(1, 4096):
    test = data[ihdr_start:ihdr_start+8] + struct.pack('>I', h) + data[ihdr_start+12:ihdr_start+17]
    if zlib.crc32(test) & 0xffffffff == stored_crc:
        data[ihdr_start+8:ihdr_start+12] = struct.pack('>I', h)
        with open('fixed.png', 'wb') as f:
            f.write(data)
        print(f"Fixed height: {h}")

# PNG chunk reordering
with open('broken.png', 'rb') as f:
    data = f.read()
sig = data[:8]
chunks = []; pos = 8
while pos < len(data):
    length = struct.unpack('>I', data[pos:pos+4])[0]
    chunks.append((data[pos+4:pos+8], data[pos+8:pos+8+length], data[pos+8+length:pos+12+length]))
    pos += 12 + length
# Sort: IHDR, ancillary, IDATs (order), IEND
ihdr = [c for c in chunks if c[0] == b'IHDR']
idat = [c for c in chunks if c[0] == b'IDAT']
iend = [c for c in chunks if c[0] == b'IEND']
other = [c for c in chunks if c[0] not in (b'IHDR', b'IDAT', b'IEND')]
with open('fixed.png', 'wb') as f:
    f.write(sig)
    for t, d, crc in ihdr + other + idat + iend:
        f.write(struct.pack('>I', len(d)) + t + d + crc)
```

### JPEG Manipulation

```python
# JPEG unused DQT table LSB
from PIL import Image
img = Image.open('challenge.jpg')
bits = []
for table_id in sorted(img.quantization.keys()):
    if table_id >= 2:  # Unreferenced tables
        for v in img.quantization[table_id]:
            bits.append(v & 1)
flag = ''.join(chr(int(''.join(str(b) for b in bits[i:i+8]), 2))
               for i in range(0, len(bits)-7, 8))

# JPEG slack space (padding to 8x8 block boundaries)
# A 253x195 image pads to 256x200 - data hidden in padding pixels
python3 jpeg_uncrop.py input.jpg --width 256 --height 200

# Nearest-neighbor interpolation stego
# Data at regular pixel intervals, downscale recovers it
magick flag.webp -interpolate nearest-neighbor -resize 256x192 hidden.png

# F5 steganography detection (DCT coefficient ratio)
import numpy as np
import jpegio
def f5_ratio(path):
    jpg = jpegio.read(path)
    coeffs = jpg.coef_arrays[0].flatten()
    coeffs = coeffs[coeffs != 0]
    c1 = np.sum(np.abs(coeffs) == 1)
    c2 = np.sum(np.abs(coeffs) == 2)
    return c1 / max(c2, 1)  # Below 0.15 = F5 modified
```

### Audio Steganography

```bash
# Spectrogram (visual stego)
sox audio.wav -n spectrogram -o spec.png -X 2000 -Y 1000

# LSB audio extraction
stegolsb wavsteg -r -i audio.wav -o out.bin -n 2 -b 1000

# DTMF tone decoding
sox audio.wav -t raw -r 22050 -e signed-integer -b 16 -c 1 - | \
    multimon-ng -t raw -a DTMF -

# Multi-track audio differential subtraction (nearly identical tracks)
ffmpeg -i video.mkv -map 0:a:0 track0.wav
ffmpeg -i video.mkv -map 0:a:1 track1.wav
sox -m track0.wav "|sox track1.wav -p vol -1" diff.wav
sox diff.wav -n spectrogram -o diff_spec.png -X 2000

# Audio waveform binary encoding (two distinct wave shapes)
python3 -c "
import wave, struct
wf = wave.open('audio.wav', 'rb')
frames = wf.readframes(wf.getnframes())
samples = struct.unpack(f'{len(frames)//2}h', frames)
bits = ''
for segment in chunks:
    bits += '1' if max(segment) > threshold else '0'
print(''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8)))
"

# DeepSound audio stego
python3 deepsound2john.py audio.wav > hash.txt
john --wordlist=rockyou.txt hash.txt
```

### PDF Steganography

```bash
# Metadata
exiftool document.pdf
pdfinfo document.pdf

# Extract text
pdftotext document.pdf - | grep -i flag

# Decompress all streams
mutool clean -d -c document.pdf clean.pdf
strings clean.pdf | grep -i flag

# Check post-EOF data
python3 -c "
data = open('file.pdf','rb').read()
eof = data.rfind(b'%%EOF')
print(data[eof+5:].hex())
"

# Extract embedded images
pdfimages -all document.pdf img
zsteg -a img-*.ppm

# Unreferenced PDF objects
qpdf --show-xref document.pdf
# Modify /Kids array and /Count to include hidden pages
```

### GIF and Video Steganography

```bash
# GIF frame differential (sequential frame comparison)
convert animated.gif frame_%03d.gif
for i in $(seq 1 100); do
    compare -fuzz 10% -compose src stego_$i.gif original_$i.gif diff_$i.gif
done

# GIF palette manipulation (palette first entry encodes binary)
# When frame count is a perfect square, grid = √frames

# Multi-stream video container (check for extra streams)
ffprobe -hide_banner file.mp4
ffmpeg -i file.mp4 -map 0:1 -c copy second_stream.mp4
ffmpeg -i file.mp4 -map 0:1 -frames:v 1 flag.jpg

# Video frame accumulation (flashing positions composite)
ffmpeg -i challenge.mp4 -vsync 0 frames/frame_%04d.png
python3 -c "
from PIL import Image
import numpy as np, os, glob
frames = sorted(glob.glob('frames/*.png'))
acc = np.zeros(np.array(Image.open(frames[0])).shape, dtype=np.float64)
for f in frames:
    acc += np.array(Image.open(f), dtype=np.float64) / len(frames)
image = Image.fromarray(np.round(acc).astype(np.uint8))
image.save('accumulated.png')
"

# MJPEG extra bytes after FFD9
python3 -c "
frames = open('video.mjpeg', 'rb').read().split(b'\xff\xd8')
hidden = b''
for frame in frames:
    if not frame: continue
    eoi = frame.find(b'\xff\xd9')
    if eoi != -1:
        hidden += frame[eoi+2:]
print(hidden.decode(errors='ignore'))
"
```

### Video Container and Codec Steganography

```bash
# MP4/MOV atom tree inspection
mp4info file.mp4
mp4file --dump file.mp4                 # Detailed atom structure
python3 -c "
import struct
with open('file.mp4', 'rb') as f:
    data = f.read()
pos = 0
while pos < len(data) - 8:
    size = struct.unpack_from('>I', data, pos)[0]
    atom = data[pos+4:pos+8]
    print(f'Offset {pos}: {atom.decode()} ({size} bytes)')
    if size == 0: break
    pos += size
"

# Extract data between atoms (padding gaps)
python3 << 'EOF'
import struct
with open('file.mp4', 'rb') as f:
    data = f.read()
pos = 0
gap_data = b''
while pos < len(data) - 8:
    size = struct.unpack_from('>I', data, pos)[0]
    if size < 8: break
    gap = data[pos + size:pos + size + 4]
    if any(b != 0 for b in gap):
        gap_data += gap
    pos += size
print('Gap data:', gap_data.decode(errors='ignore'))
EOF

# Extract custom UUID atoms
python3 << 'EOF'
import struct
with open('file.mp4', 'rb') as f:
    data = f.read()
pos = 0
while pos < len(data) - 8:
    size = struct.unpack_from('>I', data, pos)[0]
    atom = data[pos+4:pos+8]
    if atom == b'uuid':
        uuid_bytes = data[pos+8:pos+24].hex()
        payload = data[pos+24:pos+size]
        print(f'UUID: {uuid_bytes}, Payload: {payload[:64].decode(errors="ignore")}')
    if size == 0: break
    pos += size
EOF

# Audio track stego extraction from video
ffmpeg -i file.mp4 -map 0:a:0 -c copy audio_stego.aac
ffmpeg -i file.mp4 -map 0:a:0 audio_stego.wav
sox audio_stego.wav -n spectrogram -o audio_stego_spec.png
stegolsb wavsteg -r -i audio_stego.wav -o out.bin -n 2 -b 1000

# H.264 macroblock-level: DCT coefficient LSB extraction
ffmpeg -i file.mp4 -vcodec copy -bsf h264_mp4toannexb -f h264 raw.h264
python3 << 'EOF'
with open('raw.h264', 'rb') as f:
    data = f.read()
pos = 0
nal_count = 0
while pos < len(data) - 4:
    if data[pos:pos+3] == b'\x00\x00\x01' or data[pos:pos+4] == b'\x00\x00\x00\x01':
        start = pos + (4 if data[pos:pos+4] == b'\x00\x00\x00\x01' else 3)
        nal_type = data[start] & 0x1F
        if nal_type == 1:
            slice_data = data[start:start+100]
            bits = [b & 1 for b in slice_data[5:]]
            chars = ''.join(chr(int(''.join(str(b) for b in bits[i:i+8]), 2))
                          for i in range(0, len(bits)-7, 8))
            printable = ''.join(c if 32 <= ord(c) < 127 else '' for c in chars)
            if printable:
                print(f'NAL {nal_count}: {printable[:80]}')
        nal_count += 1
        pos = start + 1
    else:
        pos += 1
EOF

# Motion vector analysis
ffprobe -hide_banner -show_frames file.mp4 2>/dev/null | grep "motion_vector" | head -20

# Multi-stream video: extract all mapped streams
ffmpeg -i file.mp4 2>&1 | grep Stream
ffmpeg -i file.mp4 -map 0:2 -c copy hidden_stream.mp4
```

### Network Protocol Steganography

```bash
# TCP ISN field extraction (32-bit Initial Sequence Number)
tshark -r capture.pcap -T fields -e tcp.srcport -e tcp.seq -e tcp.ack \
  -Y "tcp.flags.syn==1 and tcp.flags.ack==0" | head -20

# Decode ISN LSB as carrier
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-T", "fields", "-e", "tcp.seq",
     "-Y", "tcp.flags.syn==1 and tcp.flags.ack==0"])
bits = [str(int(seq.strip()) & 1) for seq in out.decode().strip().split('\n') if seq.strip()]
data = bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits)-7, 8))
print('ISN LSB message:', data.decode(errors='ignore'))
EOF

# IP Identification field (16-bit, often sequential)
tshark -r capture.pcap -T fields -e ip.id -e ip.src -Y "ip" | head -30

# Detect non-random IP IDs (possible covert channel)
python3 << 'EOF'
# Proper pcap parsing: skip pcap global header + per-packet headers
import struct

# Use scapy if available; this manual parsing handles standard Ethernet pcap
with open('capture.pcap', 'rb') as f:
    data = f.read()

# Pcap global header: magic(4) + version(4) + timezone(4) + sigfigs(4) + snaplen(4) + linktype(4) = 24
if len(data) < 24:
    exit(1)
link_type = struct.unpack_from('<I', data, 20)[0]
eth_overhead = 14 if link_type == 1 else 0  # DLT_EN10MB = 1 (Ethernet)

pos = 24  # skip global header
ids = []
while pos + 16 <= len(data):
    # Per-packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16
    incl_len = struct.unpack_from('<I', data, pos + 8)[0]
    pkt_start = pos + 16
    if incl_len < 14 or pkt_start + incl_len > len(data):
        break
    # Parse Ethernet frame: dst(6) + src(6) + type(2) = 14
    eth_type = struct.unpack_from('>H', data, pkt_start + 12)[0]
    if eth_type == 0x0800:  # IPv4
        ip_hdr = pkt_start + 14
        ip_ihl = (data[ip_hdr] & 0x0F) * 4
        if ip_ihl >= 20:
            ip_id = struct.unpack_from('>H', data, ip_hdr + 2)[0]
            ids.append(ip_id)
    pos = pkt_start + incl_len

diffs = [ids[i+1] - ids[i] for i in range(len(ids)-1)]
print(f"IP IDs: {ids[:30]}...")
print(f"Diffs: {diffs[:30]}")
EOF

# HTTP header cookie value extraction
tshark -r capture.pcap -Y "http.request" -T fields -e http.cookie | head -10

# Extract binary from cookie character parity
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-Y", "http.request",
     "-T", "fields", "-e", "http.cookie"])
bits = []
for line in out.decode().strip().split('\n'):
    if not line.strip(): continue
    for ch in line:
        bits.append(str(ord(ch) & 1))
data = bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits)-7, 8))
print('Cookie bit message:', data.decode(errors='ignore'))
EOF

# DNS query name encoding
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | head -20

# Decode DNS exfiltration via hex-encoded subdomains
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-Y", "dns.qry.type==1",
     "-T", "fields", "-e", "dns.qry.name"])
for line in out.decode().strip().split('\n'):
    if not line.strip(): continue
    labels = line.strip('.').split('.')
    if len(labels) >= 3:
        try:
            decoded = bytes.fromhex(labels[0])
            if decoded.isprintable():
                print(f'DNS hex: {decoded.decode(errors="ignore")}')
        except ValueError:
            pass
EOF

# DNS TXT record abuse
tshark -r capture.pcap -Y "dns.txt" -T fields -e dns.txt -e dns.resp.name | head -10

# TLS ClientHello random bytes extraction
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields \
  -e tls.handshake.random -e tls.handshake.session_id | head -5

# Extract LSB from ClientHello random (32 bytes per connection)
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-Y", "tls.handshake.type==1",
     "-T", "fields", "-e", "tls.handshake.random"])
bits = []
for line in out.decode().strip().split('\n'):
    if not line.strip(): continue
    try:
        rand_bytes = bytes.fromhex(line.replace(':', ''))
        bits.extend(str(b & 1) for b in rand_bytes)
    except ValueError:
        pass
data = bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits)-7, 8))
print('TLS random LSB:', data.decode(errors='ignore'))
EOF

# TLS SNI field covert channel
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | head -10

# ICMP payload extraction
tshark -r capture.pcap -Y "icmp" -T fields -e data.data | head -10

# Decode ICMP echo data
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-Y", "icmp.type==8",
     "-T", "fields", "-e", "data.data"])
for line in out.decode().strip().split('\n'):
    if not line.strip(): continue
    try:
        payload = bytes.fromhex(line.replace(':', ''))
        print(f'ICMP data: {payload[:64]}')
        if b'CTF{' in payload or b'flag' in payload:
            print(f'*** FLAG FOUND: {payload}')
    except ValueError:
        pass
EOF

# ICMP timing channel: inter-packet delay encodes bits
python3 << 'EOF'
import subprocess
out = subprocess.check_output(
    ["tshark", "-r", "capture.pcap", "-Y", "icmp.type==8",
     "-T", "fields", "-e", "frame.time_epoch"])
times = [float(t) for t in out.decode().strip().split('\n') if t.strip()]
deltas = [int((times[i+1] - times[i]) * 1000) for i in range(len(times)-1)]
bits = ['1' if d >= 100 else '0' for d in deltas]
data = bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits)-7, 8))
print('Timing message:', data.decode(errors='ignore'))
EOF
```

### Specialized Techniques

```python
# Autostereogram / Magic Eye solver
import numpy as np
from PIL import Image
img = np.array(Image.open('stereogram.png'))
shift = 100  # repeat width
diff = np.abs(img[:, shift:].astype(int) - img[:, :-shift].astype(int))
Image.fromarray(diff.astype(np.uint8)).save('revealed.png')

# Arnold's Cat Map (chaotic image scramble)
def arnold_cat_map(image, n):
    assert image.shape[0] >= n and image.shape[1] >= n, "image must be at least n x n"
    result = np.zeros_like(image)
    for x in range(n):
        for y in range(n):
            result[(2*x + y) % n, (x + y) % n] = image[x, y]
    return result

# Multi-color QR code brute force (2^N binary partitions)
from itertools import product
palette = sorted(set(...))  # non-black/white colors
for bits in product([0, 1], repeat=len(palette)):
    mapping = dict(zip(palette, bits))
    # render QR candidate, scan with zbarimg

# Angecryption: AES-CBC one valid file into another
from Crypto.Cipher import AES
aes = AES.new(key, AES.MODE_CBC, iv)
result = aes.encrypt(open('input.png', 'rb').read())
# result is also a valid PNG (mask image)

# Two-layer byte+line interleaving
data = open('file.bin', 'rb').read()
a = bytes(data[0::2])  # even bytes
b = bytes(data[1::2])  # odd bytes
# Both are valid images with interleaved scanlines
```

## Bypass

When standard LSB tools find nothing: try different bit positions per RGB channel (R[2], G[1], B[0]), use conditional pixel filtering (near-black only), check all bitplanes (not just bit 0), extract palette entries not referenced by any pixel, inspect quantization tables beyond IDs 0 and 1 in JPEG. When file format parser skips content: look after EOF markers (IEND, %%EOF, FFD9), reverse the entire byte stream (byte-reversed ZIP), reorder chunks in PNG. When data is encrypted: brute-force short XOR keys with charset constraints, use known-plaintext for ZipCrypto, crack weak AES keys via frequency analysis on image data.

## Verification

Confirm by: message decoded from LSB reads as flag, hidden QR code scans successfully, spectrogram shows readable text, steghide/outguess extracts embedded file, decrypted data produces valid image/archive, reconstructed image reveals hidden pattern, reversed audio plays intelligible message.

## Pitfalls

Assuming LSB is always in bit 0 of each channel. Not checking for conditional pixel filters (only specific colors carry data). Overlooking metadata fields (EXIF, comments, xref generation numbers). Not checking after EOF markers. Using standard tools exclusively without trying custom extraction. Ignoring frequency domain entirely (FFT can hide data). Assuming single-layer stego (may need XOR -> base64 -> text with ROT18). Not checking palette-based formats for unused entries. Missing animation/progressive frames (APNG, GIF, progressive JPEG). Forgetting that standard SSTV signals may be red herrings with real data in audio LSB.
