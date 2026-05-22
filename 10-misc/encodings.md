# Encodings, Ciphers, and Data Formats

## Trigger
Load when encountering encoded text (base64, base32, hex, rot13), QR codes (single or split/chunked), esoteric programming languages (Brainfuck, Whitespace, Piet), Unicode steganography (variation selectors, tag characters), binary data hiding in IEEE 754 floats or UTF-16 mojibake, multi-layer encoding chains, or any challenge where data format detection is the primary obstacle.

## Attack Surface
Target characteristics: text strings with restricted character sets (base64: A-Za-z0-9+/=, base32: A-Z2-7=, hex: 0-9a-f), QR code images (single or grid-split), files with only whitespace/tabs/newlines (Whitespace language), text appearing as CJK mojibake (UTF-16 endianness reversal), PNG images that may be Piet code, repetitive text with small vocabulary (Brainfuck variants), and BCD-encoded or float-encoded binary data.

## Decision Tree
1. Identify encoding by character set: hex (0-9a-f only), base32 (A-Z2-7=, uppercase), base64 (A-Za-z0-9+/=), base85 (wider charset including punctuation).
2. Try decode in order of likelihood: hex first when data is all hex chars, then base64, then base32.
3. For multi-layer: decode hex -> base64 -> rot13 or similar; look for "REAL_DATA_FOLLOWS:" or troll flags.
4. For QR images: scan with zbarimg; if damaged, check finder patterns and repair.
5. For split QR chunks: reconstruct in grid order, either by structural clues or by decoding indexed directory names.
6. For esolangs: identify language by syntax (Brainfuck: +-[]<>.,, Whitespace: only spaces/tabs/newlines, Piet: PNG pixels).
7. For Unicode stego: scan text for codepoints in variation selector ranges (U+FE00-U+FE0F, U+E0100-U+E01EF) or tag block (U+E0000-U+E007F).

## Techniques

### Encoding Identification by Character Set
```
Encoding    Characters                     Example
hex         0-9 a-f A-F                    68656c6c6f
base32      A-Z 2-7 =                      NBSWY3DP
base64      A-Z a-z 0-9 + / =              aGVsbG8=
base85      !-u (ASCII 33-117)             87cURD]j7
rot13       a-z A-Z (rotated)              uryyb jbeyq
uuencode    ASCII printable + wide range   begin 644 data
ascii85     ! through u, ~ for padding     87cURD]j*<
```

### Base64 / Base32 / Hex Decoding
```bash
echo "aGVsbG8gd29ybGQ=" | base64 -d
echo "NBSWY3DPN5XSA====" | base32 -d
echo "68656c6c6f" | xxd -r -p
```

### Base85 / Ascii85 Decoding
```python
import base64
# Python's base64 module handles multiple base85 variants
# Adobe Ascii85: <~...~>
data = b"<~87cURD]j7EboQChq=>"
decoded = base64.a85decode(data, adobe=True)
print(decoded)

# RFC 1924 (Z85 variant)
# base64.b85decode()
```

### IEEE 754 Float Encoding
```python
import struct

# When a list of numbers encodes ASCII text as float32 bytes
values = [240600592, 212.2753143310547, 2.7884192016691608e+23]

decoded = b''
for v in values:
    decoded += struct.pack('>f', v)  # Big-endian single precision
    # Try '<f' for little-endian, '>d' for double precision
print(decoded)  # b'MetaCTF{fl04...'
```

### UTF-16 Endianness Reversal (Mojibake Fix)
```python
# When text appears as CJK characters due to endianness mismatch
mojibake = "你好世界"  # example

# If encoded as UTF-16-LE but decoded as UTF-16-BE:
fixed = mojibake.encode('utf-16-be').decode('utf-16-le')

# If encoded as UTF-16-BE but decoded as UTF-16-LE:
fixed = mojibake.encode('utf-16-le').decode('utf-16-be')
```

### BCD (Binary-Coded Decimal) Decoding
```python
def bcd_decode(data):
    """Each nibble encodes one decimal digit. Each byte = 2 digits.
    NOTE: This is a simplified demo that produces a nibble-ASCII transform,
    not true BCD decoding. Real BCD decoding produces numeric digits, not text."""
    digits = ''.join(f'{(b>>4)&0xf}{b&0xf}' for b in data)
    # Convert digit pairs to ASCII
    return ''.join(chr(int(digits[i:i+2])) for i in range(0, len(digits), 2))

# For 1.5x ratio challenges (BCD has 2:1 nibble-to-digit ratio)
```

### Multi-Layer Auto-Decoding
```python
import base64

def auto_decode(data):
    """Recursively decode through hex -> base64 -> etc."""
    while True:
        data = data.strip()
        if data.startswith('REAL_DATA_FOLLOWS:'):
            data = data.split(':', 1)[1]

        # Priority: hex FIRST when ambiguous (both hex and base64 accept 0-9 a-f)
        if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
            data = bytes.fromhex(data).decode('ascii', errors='replace')
        elif set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='):
            try: data = base64.b64decode(data).decode('ascii', errors='replace')
            except Exception: break
        elif set(data) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='):
            try: data = base64.b32decode(data).decode('ascii', errors='replace')
            except Exception: break
        else:
            break
    return data

# Ignore troll flags ("Not flag", "fake") -- look for "keep decoding" markers
```

### ROT13 / Caesar Brute Force
```bash
echo "uryyb" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
# Common ROT13 patterns: "gur" = "the", "synt" = "flag"
```

```python
def caesar_bruteforce(text):
    for shift in range(26):
        decoded = ''.join(
            chr((ord(c) - 65 - shift) % 26 + 65) if c.isupper()
            else chr((ord(c) - 97 - shift) % 26 + 97) if c.islower()
            else c for c in text)
        print(f"{shift:2d}: {decoded}")
```

### QR Code Decoding
```bash
zbarimg qrcode.png              # Standard decode
zbarimg -S*.enable qr.png       # All barcode types
qrencode -o out.png "data"      # Encode
```

```python
# Programmatic decode
from pyzbar.pyzbar import decode
from PIL import Image
print(decode(Image.open('qrcode.png')))
```

### Damaged QR Repair
```python
import numpy as np
from PIL import Image

img = Image.open('damaged_qr.png')
arr = np.array(img)
gray = np.mean(arr, axis=2)
binary = (gray < 128).astype(int)

# Find QR bounds
rows = np.any(binary, axis=1)
cols = np.any(binary, axis=0)
rmin, rmax = np.where(rows)[0][[0, -1]]
cmin, cmax = np.where(cols)[0][[0, -1]]

# Check finder patterns (3 corners)
qr = binary[rmin:rmax+1, cmin:cmax+1]
print("Top-left finder:", qr[0:7, 0:7].sum())  # Should be ~25

# QR version formula: modules_per_side = (version * 4) + 17
```

### QR Chunk Reassembly (Indexed Directories)
```python
import os, base64, math
from PIL import Image

# Directory names encode chunk index as base64 (e.g., "MDAx" -> "001")
chunks = []
for dirname in os.listdir('chunks/'):
    index = int(base64.b64decode(dirname).decode())
    tile = Image.open(f'chunks/{dirname}/tile.png')
    chunks.append((index, tile))

# Sort by index and arrange in grid
chunks.sort(key=lambda x: x[0])
n = len(chunks)
side = int(math.isqrt(n))
tile_w, tile_h = chunks[0][1].size

canvas = Image.new("RGB", (side * tile_w, side * tile_h), (255, 255, 255))
for i, (_, tile) in enumerate(chunks):
    r, c = divmod(i, side)
    canvas.paste(tile, (c * tile_w, r * tile_h))

canvas.save('reconstructed_qr.png')
```

### Unicode Variation Selector Steganography
```python
# Variation Selectors Supplement (U+E0100-U+E01EF) encode ASCII
data = open('README.md', 'r').read().strip()
hidden = data[1:]  # Skip initial visible character

flag = ''.join(chr((ord(c) - 0xE0100) + 16) for c in hidden)
print(flag)

# Detection: check for codepoints in U+E0100-U+E01EF
any(0xE0100 <= ord(c) <= 0xE01EF for c in text)
```

### Unicode Tags Block Steganography (U+E0000-U+E007F)
```python
import urllib.parse

# Tag characters mirror ASCII 1:1 via offset 0xE0000
url = "http://example.com/page#%F3%A0%81%B5%F3%A0%81%B4...Visible%20Text"
decoded = urllib.parse.unquote(urllib.parse.urlparse(url).fragment)

flag = ''.join(
    chr(ord(ch) - 0xE0000)
    for ch in decoded
    if 0xE0000 <= ord(ch) <= 0xE007F
)

# Detection: URL percent sequences start with %F3%A0%80 or %F3%A0%81
# Python check: any(0xE0000 <= ord(c) <= 0xE007F for c in text)
```

### base65536 CJK Unicode Encoding
```bash
# base65536 maps 2 bytes to 1 CJK Unicode codepoint
# File appears as wall of Chinese characters

# Decode with npm
echo -n "宝䀈䀋..." | base65536 --decode > out.bin

# Or with Python
pip install base65536
python3 -c "import base65536, sys; sys.stdout.buffer.write(base65536.decode(open('blob.txt').read()))"
```

### Whitespace Language
```
IMP + opcode encoding:
S S + sign + binary + L    PUSH number
T L S S                    POP + output as ASCII
L L L                      EXIT

S = space, T = tab, L = linefeed
```

### Brainfuck Variant Identification
Identify by small vocabulary (5-8 unique words), long line repetition. Map by frequency:
- Most frequent word -> `+` (increment)
- Line terminator -> `.` (output)
- Appears in pairs -> `[` / `]` (loop)

```python
from collections import Counter
words = content.split()
freq = Counter(words)
# Map theme words to BF operations
mapping = {'arch': '+', 'linux': '-', 'i': '>', 'use': '<',
           'the': '[', 'way': ']', 'btw': '.'}
bf = ''.join(mapping.get(w, '') for w in words)
# Execute via standard BF interpreter
```

### Multi-Stage URL Encoding Chain
```python
import base64, codecs

# Hop 1: Base64 -> URL
hop1 = "aHR0cHM6Ly9naXN0Lmdp..."
url2 = base64.b64decode(hop1).decode()

# Hop 2: Hex-encoded URL
hop2 = "68747470733a2f2f..."
url3 = bytes.fromhex(hop2).decode()

# Hop 3: ROT13 flag
hop3 = "hgsynt{...}"
flag = codecs.decode(hop3, 'rot_13')

# Look for contextual hints ("Three letters follow" = hex)
```

## Bypass
- If QR is too damaged to scan, try reconstructing the finder patterns manually (7x7 template) and use error correction (QR can recover up to 30% damage).
- If multi-layer decoding hits a dead end, try reversing the data between layers (sometimes data is reversed or XORed between encoding steps).
- If the charset is ambiguous (data contains only hex chars), try hex FIRST before base64 -- hex is often the correct first layer.
- For Unicode stego, if variation selectors are stripped, check if the data uses invisible Unicode characters from Tags block (U+E0000) or zero-width joiners (U+200D).

## Verification
- Decoded output starts with a known plaintext pattern (flag format, readable English, or file magic bytes).
- QR code scans cleanly with `zbarimg` after reconstruction or repair.
- Whitespace interpreter produces printable ASCII output.
- Float packing produces readable ASCII text (not binary garbage).
- Unicode stego extraction yields a valid flag string.

## Pitfalls
- Data containing only hex characters is ambiguous -- could be hex, could be base64. When all characters are 0-9 a-f, decode as hex first.
- QR finder patterns are essential for decoding; if the top-left finder is corrupted, try reconstructing from the other two corners.
- Brainfuck variant mapping may need `+`/`-` or `>`/`<` swapped if the output is garbage.
- Multi-layer encoding chains may have arbitrary depth; always assume "one more layer" when the output still looks encoded.
- Unicode tag characters (U+E0000-U+E007F) are invisible in most text renderers but affect byte length -- a text that seems normal but has unusual byte length is suspect.
- base65536 encoded data will be LARGER on disk than the original (each codepoint is 3-4 UTF-8 bytes for only 2 bytes of data).
