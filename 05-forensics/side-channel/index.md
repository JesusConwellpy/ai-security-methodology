# Side-Channel and Hardware Forensics

## Trigger

Load when presented with: power trace data (.npy, .csv, .json with power samples), electromagnetic emission recordings, acoustic recordings (keystrokes, processor hum), logic analyzer captures (.sal, .csv, .vcd, .bin), signal capture files (.wav of serial/UART/I2C), VGA/HDMI/DisplayPort signal dumps, software-defined radio captures (.iq, .cu8, .cs8), RF signal recordings (.sub from Flipper Zero), or challenges involving cryptographic side-channel attacks, hardware signal decoding, or peripheral traffic analysis.

## Attack Surface

Evidence characteristics: signal capture method (oscilloscope, logic analyzer, SDR, microphone) determines data format and resolution, sample rate affects timing precision, number of channels (single-ended vs differential), quantization bit depth, trigger alignment (whether traces are synchronized), ambient noise level, coding scheme (NRZ, Manchester, 8b/10b), protocol framing (start bits, stop bits, parity), and device-specific protocol variations.

## Decision Tree

1. Identify signal type: power trace, electromagnetic, acoustic, logic, RF, video signal
2. Determine protocol/encoding: UART, I2C, SPI, TMDS, 8b/10b, analog video, custom encoding
3. Extract timing information: sample rate, bit period, frame structure
4. Align/synchronize traces if needed (trigger alignment)
5. For power traces: apply differential power analysis (DPA)
6. For logic captures: reconstruct data bits from state transitions
7. For video signals: reconstruct frames from sync + pixel data
8. For audio signals: spectrogram analysis, keystroke classification
9. For RF captures: demodulation, pulse timing analysis
10. Convert decoded bits/values to human-readable form

## Techniques

### Differential Power Analysis (DPA)

```python
import numpy as np
# Power traces shape: (positions, guesses, traces, samples)
data = np.load('power_traces.npy')
n_positions, n_guesses, n_traces, n_samples = data.shape
key_digits = []
for pos in range(n_positions):
    # Average traces to reduce noise, find sample with max variance
    avg_power = data[pos].mean(axis=1)  # (guesses, samples)
    leak_sample = np.argmax(avg_power.var(axis=0))
    best_guess = np.argmax(avg_power[:, leak_sample])
    key_digits.append(best_guess)
key = ''.join(str(d) for d in key_digits)
```

### Keyboard Acoustic Side-Channel

```python
import numpy as np, librosa
from scipy.signal import find_peaks
from sklearn.neighbors import KNeighborsClassifier

sr, audio = librosa.load('flag.wav', sr=None, mono=True)
win = int(0.01 * sr)  # 10ms captures impact transient
energy = np.array([np.sum(audio[i:i+win]**2) for i in range(0, len(audio)-win, win)])
peaks, _ = find_peaks(energy, height=0.03*energy.max(), distance=int(0.175*sr/win))

def extract_features(audio, sr, peak):
    seg = audio[max(0, peak-win//2):peak+win//2]
    mfcc = librosa.feature.mfcc(y=seg.astype(float), sr=sr, n_mfcc=20)
    return np.concatenate([mfcc.mean(axis=1), mfcc.std(axis=1)])

# X_ref, y_ref must come from labeled training data (known keystrokes
# recorded on the same keyboard/microphone setup). X_ref rows are feature
# vectors (MFCC means + stds); y_ref is the corresponding key label.
knn = KNeighborsClassifier(n_neighbors=5).fit(X_ref, y_ref)
flag = ''.join(knn.predict([extract_features(audio, sr, p) for p in peaks]))
```

### VGA Signal Decoding

```python
import numpy as np
from PIL import Image
data = open('vga.bin', 'rb').read()
TOTAL_W, TOTAL_H = 800, 525   # 640x480 active + blanking
BYTES_PER_SAMPLE = 5  # R, G, B, hsync, vsync
samples = np.frombuffer(data, dtype=np.uint8).reshape(-1, BYTES_PER_SAMPLE)
frame = samples.reshape(TOTAL_H, TOTAL_W, BYTES_PER_SAMPLE)
active = frame[:480, :640, :3]  # Crop blanking
img = (active.astype(np.uint16) * 4).clip(0, 255).astype(np.uint8)  # 6-bit to 8-bit
Image.fromarray(img).save('vga_output.png')
```

### HDMI TMDS Decoding

```python
def tmds_decode(sym):
    """Decode 10-bit TMDS symbol to 8-bit value."""
    bits = [(sym >> i) & 1 for i in range(10)]
    d = [1 - bits[i] for i in range(8)] if bits[9] else bits[:8]
    q = [d[0]]
    for i in range(1, 8):
        q.append(d[i] ^ (q[i-1] if bits[8] else q[i-1] ^ 1))
    return sum(q[i] << i for i in range(8))
```

### DisplayPort LFSR Descrambler

```python
def lfsr_descramble(data):
    """x^16 + x^5 + x^4 + x^3 + 1 LFSR, resets on control symbols."""
    lfsr, result = 0xFFFF, []
    for byte in data:
        out = byte
        for bit_idx in range(8):
            fb = (lfsr >> 15) & 1
            out ^= (fb << bit_idx)
            new = ((lfsr >> 15) ^ (lfsr >> 4) ^ (lfsr >> 3) ^ (lfsr >> 2)) & 1
            lfsr = ((lfsr << 1) | new) & 0xFFFF
        result.append(out & 0xFF)
    return bytes(result)
```

### Saleae Logic 2 UART Decode

```bash
# .sal is ZIP containing digital-*.bin + meta.json
unzip capture.sal
# Delta-encoded transitions: each value = samples between state changes
# Signal toggles HIGH/LOW at each delta. Detect start bit (LOW),
# sample 8 data bits at bit center positions, LSB first.
```

### Serial UART from WAV Audio

```python
import struct
with open('signal.wav', 'rb') as f:
    header = f.read(44)
    samples = []
    while True:
        d = f.read(2)
        if not d: break
        samples.append(struct.unpack('<h', d)[0])

bits = [1 if s > 0 else 0 for s in samples]
output = []
i = 0
while i < len(bits) - 11:
    if bits[i] == 0:  # Start bit
        byte_val = sum(bits[i+1+j] << j for j in range(8))  # LSB first
        output.append(byte_val)
        i += 11
    else:
        i += 1
print(bytes(output))
```

### I2C Bus Protocol Decoding

```python
def decode_i2c(sda, scl):
    """Decode I2C from logic capture. SDA=ch0, SCL=ch1."""
    out = []; byte = 0; bits = 0; frame = False
    for i in range(len(scl) - 1):
        if sda[i]==1 and sda[i+1]==0 and scl[i]==1:  # START
            frame = True; bits = 0; byte = 0; continue
        if sda[i]==0 and sda[i+1]==1 and scl[i]==1:  # STOP
            frame = False; continue
        if frame and scl[i]==0 and scl[i+1]==1:  # rising edge
            if bits < 8:
                byte = (byte << 1) | sda[i+1]; bits += 1
            elif bits == 8:
                out.append(byte); bits = 0; byte = 0
    return out
```

### USB HID Mouse/Pen Drawing Recovery

```python
import struct
from PIL import Image, ImageDraw

# 7-byte HID report: btn(1), mode(1), dx(2), dy(2) as int16 LE
# Extract from PCAP: tshark -r capture.pcap -T fields -e usb.capdata
pts = {1: [], 2: []}
x = y = 0
with open('hid_data.txt') as f:
    for line in f:
        raw = bytes.fromhex(line.strip().replace(':', ''))
        if len(raw) < 7: continue
        dx, dy = struct.unpack('<hh', raw[2:6])
        x += dx; y += dy
        pts[raw[1]].append((x, y))

SCALE = 5
for mode, coords in pts.items():
    if not coords: continue
    mx = min(p[0] for p in coords) - 100
    my = min(p[1] for p in coords) - 100
    img = Image.new('RGB', (800, 600), 'white')
    draw = ImageDraw.Draw(img)
    for i in range(1, len(coords)):
        if abs(coords[i][0]-coords[i-1][0]) < 50 and abs(coords[i][1]-coords[i-1][1]) < 50:
            draw.line([((coords[i-1][0]-mx)*SCALE, (coords[i-1][1]-my)*SCALE),
                       ((coords[i][0]-mx)*SCALE, (coords[i][1]-my)*SCALE)], fill='black', width=3)
    img.save(f'mode_{mode}.png')
```

### USB HID Keyboard Decoding

```python
# HID report: byte0=modifiers, bytes2-7=keycodes (max 6 simultaneous)
# Full keycode map at: https://usb.org/document-library/hid-usage-tables-12
HID_MAP = {0x04:'a', 0x05:'b', 0x06:'c', 0x07:'d', 0x08:'e', 0x09:'f',
    0x0a:'g', 0x0b:'h', 0x0c:'i', 0x0d:'j', 0x0e:'k', 0x0f:'l',
    0x10:'m', 0x11:'n', 0x12:'o', 0x13:'p', 0x14:'q', 0x15:'r',
    0x16:'s', 0x17:'t', 0x18:'u', 0x19:'v', 0x1a:'w', 0x1b:'x',
    0x1c:'y', 0x1d:'z', 0x1e:'1', 0x1f:'2', 0x20:'3', 0x21:'4',
    0x22:'5', 0x23:'6', 0x24:'7', 0x25:'8', 0x26:'9', 0x27:'0',
    0x28:'\n', 0x2c:' ', 0x2d:'-', 0x2e:'=',
    0x4f:'\x90', 0x50:'\x91', 0x51:'\x92', 0x52:'\x93'}  # arrows

SHIFT_MAP = {'1':'!', '2':'@', '3':'#', '4':'$', '5':'%', '6':'^',
    '7':'&', '8':'*', '9':'(', '0':')', '-':'_', '=':'+'}

text = ""
for report in reports:
    kc = report[2]
    if kc == 0: continue
    char = HID_MAP.get(kc, '')
    if report[0] & 0x22:  # Shift
        char = SHIFT_MAP.get(char, char.upper())
    text += char
```

### USB Keyboard LED Morse Extraction

```python
from scapy.all import rdpcap
packets = rdpcap('usb_capture.pcap')
signals = [(p.time, bytes(p)[30]) for p in packets
           if len(bytes(p)) >= 35 and bytes(p)[30] in (0x01, 0x03)]
# 0x01=LED off, 0x03=LED on. Duration >300ms = dash, shorter = dot
morse = ''
for i in range(0, len(signals)-1, 2):
    d = signals[i+1][0] - signals[i][0]
    morse += '-' if d > 0.3 else '.'
```

### Caps-Lock LED Morse from Video

```python
import cv2
vidcap = cv2.VideoCapture('security_camera.mp4')
morse, prev = [], None
while True:
    ret, frame = vidcap.read()
    if not ret: break
    r, g, b = frame[58, 686]  # Caps-Lock LED pixel
    on = r > 200 and g > 200 and b > 200
    morse.append(on)
# Convert on/off durations to Morse dots/dashes, map via MORSE_MAP
```

### Tektronix Logic Analyzer CSV

```python
import csv
with open('capture.csv') as f:
    reader = csv.reader(f)
    prev_clk, pixels = 0, []
    for row in reader:
        try: clk = int(row[1])
        except ValueError: continue
        if prev_clk == 0 and clk == 1:  # rising edge
            pixels.append((int(row[2]), int(row[3]), int(row[4])))
        prev_clk = clk
```

### Linux input_event Keylogger Parsing

```python
import struct
with open('dump.bin', 'rb') as f:
    while data := f.read(24):
        tv_sec, tv_usec, type_, code, value = struct.unpack('<QQHHi', data)
        if type_ == 1 and value == 1:  # EV_KEY, key press
            print(f"Keycode: {code}")  # Map via input-event-codes.h
```

### Voyager Golden Record Audio

```python
import numpy as np
from scipy.io import wavfile
from PIL import Image

rate, audio = wavfile.read('golden_record.wav')
threshold = np.min(audio) * 0.7
sync_idx = np.where(audio < threshold)[0]
pulses = [sync_idx[0]]
for i in range(1, len(sync_idx)):
    if sync_idx[i] - sync_idx[i-1] > 100:
        pulses.append(sync_idx[i])

lines = []
for i in range(len(pulses)-1):
    line = audio[pulses[i]:pulses[i+1]]
    lines.append(np.interp(np.linspace(0, len(line)-1, 512), np.arange(len(line)), line))
img = np.array(lines)
img = ((img - img.min()) / (img.max() - img.min()) * 255).astype(np.uint8)
Image.fromarray(img).save('voyager_image.png')
```

### GBA USB Framebuffer Extraction

```python
from PIL import Image
from scapy.all import rdpcap
img = Image.new('RGB', (240, 160))
for p in [p for p in rdpcap('cap.pcap') if p.haslayer('Raw')]:
    d = bytes(p.Raw)
    if d[3] == 0x06:  # type 6 = memory dump
        for i in range(38400):
            rgb = int.from_bytes(d[4+2*i:6+2*i], 'little')
            img.putpixel((i % 240, i // 240),
                ((rgb>>8)&0xF8, (rgb>>3)&0xFC, (rgb<<3)&0xF8))
img.save('screen.png')
```

### CD Audio Disc Image Steganography

Raw CD Digital Audio (.cdda) files encode visual data as pit/land patterns using only two byte values. Data is CIRC-interleaved across ~108 groups (~2592 bytes) per iteration and must be de-interleaved before rendering as a spiral disc image. The spiral geometry uses increasing track length per revolution. Calibrate geometry parameters (tr0, dtr, r0, scale) using a known reference image before decoding the target file.

### Flipper Zero .sub File

Flipper `.sub` files contain raw RF signal data in RAW_Data. Filter noise bytes (0x80-0xFF), expand batch variable references, and XOR with challenge hint text to recover the flag.

## Bypass

When standard analyzers fail: manually implement protocol decoders from raw samples (TMDS, 8b/10b, I2C). When signal-to-noise ratio is low: average multiple aligned traces for DPA, use bandpass filters for acoustic classification. When trigger alignment is missing: correlate using known reference patterns. When standard SSTV decoders fail on high-bandwidth signals: implement custom FM demodulation via arccos + derivative. When Volatility fails for hardware memory dumps: use GIMP raw import for framebuffer extraction.

## Verification

Confirm by: DPA recovers correct cryptographic key, VGA/HDMI frame renders recognizable image, UART decode produces readable ASCII text, keyboard reconstruction produces the typed sequence, Morse from LED matches flag, acoustic classification reproduces typed password, logic analyzer data decodes to valid protocol traffic, voyager audio yields visible image.

## Pitfalls

Forgetting to crop VGA blanking region (total frame > visible area). Not scaling 6-bit color to 8-bit (multiply by 4). Overlooking UART polarity inversion (try both initial_state=0 and 1). Wrong baud rate assumption in UART decoding. Using too large a window for acoustic keystroke analysis (10ms optimal for impact transient, 20-30ms adds release noise). Forgetting CIRC de-interleaving for CD audio disc images. Not accounting for signal attenuation in power traces (normalize before comparison). LFSR scrambler reset points must be correctly identified (DisplayPort). I2C signal SDA/SCL channel assignment reversed. HDMI TMDS bit ordering (check MSB vs LSB in 10-bit symbol).
