# RF and SDR Signal Analysis

## Trigger
Load when analyzing raw IQ (In-phase/Quadrature) data files from software-defined radio captures, decoding digital modulations (QAM, PSK, ASK, FSK), recovering symbols from constellation diagrams, identifying carrier frequency offsets causing constellation rotation, performing timing recovery, or analyzing demodulated data frames from wireless signals.

## Attack Surface
Target characteristics: raw IQ sample files (cf32/cs16/cu8 formats) from SDR receivers like RTL-SDR, GNU Radio, or HackRF; constellation diagrams showing circular or spiral patterns (indicating carrier/timing offsets); signals with unknown modulation order, pulse shaping, and framing; recorded signals from IoT devices (weather sensors, tire pressure monitors, garage openers) often using simple OOK/FSK modulations.

## Decision Tree
1. Identify IQ file format: try cf32 (complex64), cs16 (int16 interleaved), or cu8 (uint8 RTL-SDR raw).
2. Load data and compute FFT to find occupied bands and signal bandwidth.
3. Frequency-shift the signal of interest to baseband and low-pass filter.
4. Estimate symbol rate via cyclostationary analysis (square magnitude FFT).
5. Determine modulation type: QAM (constellation grid), PSK (circle), ASK/OOK (amplitude only).
6. Perform carrier frequency recovery (decision-directed PLL) to stop constellation rotation.
7. Perform timing recovery (Mueller-Muller or Gardner) to sample at optimal symbol points.
8. Demodulate symbols to bits and decode framing (sync pattern, start/end delimiters).

## Techniques

### IQ File Format Loading
```python
import numpy as np

# cf32: GNU Radio default, 32-bit complex float
iq = np.fromfile('signal.cf32', dtype=np.complex64)

# cs16: complex signed 16-bit, interleaved I/Q
raw = np.fromfile('signal.cs16', dtype=np.int16)
iq = raw[0::2] + 1j * raw[1::2]

# cu8: RTL-SDR raw, unsigned 8-bit
raw = np.fromfile('signal.cu8', dtype=np.uint8)
iq = (raw[0::2] - 127.5) / 127.5 + 1j * (raw[1::2] - 127.5) / 127.5
```

### Spectrum Analysis
```python
from scipy import signal

# FFT spectrum to identify occupied bands
fft_data = np.fft.fftshift(np.fft.fft(iq[:4096]))
freqs = np.fft.fftshift(np.fft.fftfreq(4096))
power_db = 20 * np.log10(np.abs(fft_data) + 1e-10)

# Plot to identify signal center frequency and bandwidth
# Look for peaks above noise floor
```

### Cyclostationary Symbol Rate Estimation
```python
# Square magnitude reveals symbol rate peak
x2 = np.abs(iq_filtered) ** 2
fft_x2 = np.abs(np.fft.fft(x2, n=65536))

# Peak in fft_x2 = symbol rate
# samples_per_symbol = 1 / peak_normalized_freq

# Bandwidth vs symbol rate: BW = Rs * (1 + alpha)
# where alpha is roll-off factor (0 to 1)
```

### Frequency Shift to Baseband
```python
center_freq = 0.14  # Normalized frequency of band center
t = np.arange(len(iq))
baseband = iq * np.exp(-2j * np.pi * center_freq * t)

# Low-pass filter to isolate the band
lpf = signal.firwin(101, bandwidth/2, fs=1.0)
filtered = signal.lfilter(lpf, 1.0, baseband)
```

### QAM-16 Demodulation with Carrier Recovery
```python
# 2nd order PLL for decision-directed carrier recovery
carrier_bw = 0.02
damping = 1.0
theta_n = carrier_bw / (damping + 1/(4*damping))
Kp = 2 * damping * theta_n       # Proportional gain
Ki = theta_n ** 2                # Integral gain

carrier_phase = 0.0
carrier_freq = 0.0

constellation = [...]  # QAM-16 constellation points (16 complex values)

for raw_sample in filtered_samples:
    # De-rotate by current phase estimate
    symbol = raw_sample * np.exp(-1j * carrier_phase)

    # Find nearest constellation point (decision)
    nearest = min(constellation, key=lambda p: abs(symbol - p))

    # Phase error (decision-directed)
    error = np.imag(symbol * np.conj(nearest)) / (abs(nearest) ** 2 + 0.1)

    # Update 2nd order loop
    carrier_freq += Ki * error
    carrier_phase += Kp * error + carrier_freq
```

### Mueller-Muller Timing Recovery
```python
def mueller_muller_error(y, y_prev, d, d_prev):
    """Timing error detector. y=received, d=decision."""
    re_part = (np.real(y) - np.real(y_prev)) * np.real(d_prev)
    re_part -= (np.real(d) - np.real(d_prev)) * np.real(y_prev)
    im_part = (np.imag(y) - np.imag(y_prev)) * np.imag(d_prev)
    im_part -= (np.imag(d) - np.imag(d_prev)) * np.imag(y_prev)
    return re_part + im_part
```

### Automatic Gain Control
```python
# Normalize signal power to match constellation
target_power = np.mean([abs(p) ** 2 for p in constellation])
measured_power = np.mean(np.abs(filtered) ** 2)
scale = np.sqrt(target_power / measured_power)
filtered *= scale
```

### Symbol-to-Bit Demapping (QAM-16)
```python
# QAM-16: each symbol = 4 bits (2 I bits, 2 Q bits)
# GNU Radio default mapping is NOT Gray code -- check the map

def symbol_to_bits(symbol, constellation_map):
    """Map received symbol to its 4-bit value."""
    nearest = min(range(len(constellation_map)),
                  key=lambda i: abs(symbol - constellation_map[i]))
    return nearest  # 0-15, convert to 4 bits
```

### Framing Recovery
```python
# Typical frame structure:
# [Sync/Idle pattern] [Start delimiter] [Data payload] [End delimiter]

# Idle pattern repeats while link is idle
# Start delimiter = unique symbol (e.g., 0)
# Data = nibble pairs (QAM-16: high nibble first, low nibble)
# End delimiter = same as start

# The idle pattern may contain the delimiter value
# Distinguish by context: part of 16-symbol repeating pattern vs. isolated symbol
```

## Bypass
- If constellation shows circles (constant frequency offset), increase the PLL carrier bandwidth or manually search frequency offsets by incrementally adjusting center_freq.
- If constellation shows spirals (drifting frequency), the loop filter bandwidth may be too narrow -- increase `carrier_bw` for faster tracking.
- If timing recovery fails, try alternative timing error detectors (Gardner instead of Mueller-Muller for BPSK/QPSK).
- For 4-fold ambiguity in DD carrier recovery (locks at 0/90/180/270 degrees rotation), try all four rotations and check which produces valid ASCII.
- If the signal is very noisy, apply a matched filter (RRC filter) matched to the transmitter's pulse shaping before detection.
- If the modulation order is unknown, try BPSK (1 bit/symbol), QPSK (2), 8-PSK (3), QAM-16 (4), QAM-64 (6) in order of increasing complexity.

## Verification
- Constellation diagram shows clearly separated points in a grid (QAM) or on a circle (PSK) after carrier recovery.
- Demodulated bits contain a known framing pattern (sync word, start delimiter).
- Decoded payload produces readable ASCII text or matches a known data format.
- Signal bandwidth matches expected symbol rate: BW = Rs * (1 + alpha).
- Cyclostationary peak confirms symbol rate estimate.

## Pitfalls
- GNU Radio's default QAM-16 constellation mapping is NOT Gray code -- always verify the symbol-to-bit mapping from the challenge specification.
- Frequency offset causes circles in the constellation, not just rotation -- a slowly rotating constellation is a sign of residual offset after PLL lock.
- Carrier recovery has 4-way phase ambiguity (0/90/180/270); demodulated data may need rotation + bit reordering.
- RC vs RRC pulse shaping at the transmitter determines whether the receiver needs a matched filter -- RC means no matched filter needed (just sample at symbol rate), RRC means apply matched RRC filter at the receiver.
- "Samples per symbol" is not the same as "samples per second" -- the SDR sampling rate is typically much higher than the symbol rate.
- IQ data files can be very large; process in chunks and use memory mapping for files > 1GB.
