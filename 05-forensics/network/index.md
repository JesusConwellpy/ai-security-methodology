# Network Forensics

## Trigger

Load when presented with: packet capture files (.pcap, .pcapng), network traffic logs, HTTP/S traffic dumps, wireless captures, DNS logs, netflow data, or challenges involving network communication analysis, exfiltration detection, protocol decoding, credential extraction, or covert channel discovery.

## Attack Surface

Evidence characteristics: capture format version (pcap vs pcapng), link layer type (Ethernet, WiFi, loopback), protocol encapsulation depth, TLS encryption strength, authentication mechanisms in use, application-layer protocol structure, timestamp precision, interface count in multi-interface captures, and file integrity (corrupted headers, truncated packets).

## Decision Tree

1. Initial triage: `tshark -r capture.pcap -q -z io,phs` to see protocol hierarchy
2. Extract HTTP objects: `tshark -r capture.pcap --export-objects http,/tmp/obj`
3. Search for flag strings: `tcpdump -r capture.pcap -A | grep -i flag`
4. Generate IP conversation stats: `tshark -r capture.pcap -q -z conv,ip`
5. Follow TCP streams: `tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream>"`
6. TLS decryption: import keylog file or RSA key into Wireshark
7. WiFi decryption: `aircrack-ng` then `airdecap-ng`
8. PCAP repair: `pcapfix -d corrupted.pcap`
9. Examine ICMP/ARP/DNS packets for covert channels
10. Extract USB audio / HID data from peripheral captures

## Techniques

### Basic Triage and Analysis

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# IP conversation statistics
tshark -r capture.pcap -q -z conv,ip

# TCP conversation statistics
tshark -r capture.pcap -q -z conv,tcp

# Filter established connections (SYN-ACK)
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" \
  -T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort -u

# Follow TCP stream
tshark -r capture.pcap -q -z "follow,tcp,ascii,0"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,/tmp/http_objects

# Filter containing specific string
tshark -r capture.pcap -Y "frame contains \"flag\""

# Export files by protocol
tshark -r capture.pcap --export-objects smb,/tmp/smb_objects
```

### TLS/SSL Decryption

```bash
# Method 1: SSLKEYLOGFILE (client-side key logging)
# Set before capture:
export SSLKEYLOGFILE=/tmp/sslkeys.log
# Import into Wireshark:
# Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename

# Method 2: RSA private key
# Wireshark: Edit > Preferences > Protocols > TLS > RSA keys list
# Format: IP,Port,Protocol,KeyFile

# Method 3: Weak RSA factorization
openssl x509 -in public.der -inform DER -noout -modulus
# Factor modulus with factordb or yafu
python rsatool.py -p <p> -q <q> -e 65537 -o server.key
```

### Credential Extraction

```bash
# HTTP POST data
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e http.file_data

# FTP credentials
tshark -r capture.pcap -Y "ftp.request.command == USER or ftp.request.command == PASS" \
  -T fields -e ftp.request.command -e ftp.request.arg

# NTLMv2 hash from SMB
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.ntlmv2_response.ntproofstr -e ntlmssp.auth.username

# Extract and crack NTLMv2
python3 -c "
import hashlib, hmac
from Crypto.Hash import MD4
def try_password(password, username, domain, server_challenge, blob, expected_proof):
    nt_hash = MD4.new(password.encode('utf-16-le')).digest()
    identity = (username.upper() + domain).encode('utf-16-le')
    ntlmv2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()
    proof = hmac.new(ntlmv2_hash, server_challenge + blob, hashlib.md5).digest()
    return proof == expected_proof
"
# hashcat mode 5600 for NTLMv2
hashcat -m 5600 ntlmv2_hash.txt wordlist.txt
```

### WiFi Decryption

```bash
# Identify networks
aircrack-ng capture.pcapng

# Crack WPA handshake
aircrack-ng -a 2 -w rockyou.txt capture.pcapng

# Decrypt traffic with key
airdecap-ng -p "passphrase" -e "SSID" capture.pcapng

# Analyze decrypted traffic
wireshark capture-dec.pcapng
```

### Covert Channel Detection

```bash
# TCP flag covert channel (6 flag bits = base64)
# Extract packets with non-standard flag combinations
tshark -r capture.pcap -Y "tcp.dstport == 5748" -T fields -e tcp.flags

# ICMP payload extraction
tshark -r capture.pcap -Y "icmp.type == 8" -T fields -e icmp.data

# DNS query name steganography
tshark -r capture.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name

# Inter-packet timing analysis
tshark -r capture.pcap -Y "frame.interface_id == 2" -T fields -e frame.time_epoch

# DNS trailing byte binary encoding
python3 -c "
from scapy.all import rdpcap, DNS, DNSQR
packets = rdpcap('challenge.pcap')
bits = []
for pkt in packets:
    if pkt.haslayer(DNSQR):
        raw = bytes(pkt[DNS])
        qname = pkt[DNSQR].qname
        expected_len = 12 + len(qname) + 2 + 2  # header + qname + qtype + qclass
        if len(raw) > expected_len:
            trailing = raw[expected_len:]
            for b in trailing:
                bits.append(chr(b))
bitstring = ''.join(bits)
flag = ''.join(chr(int(bitstring[i:i+8], 2)) for i in range(0, len(bitstring)-7, 8))
print(flag)
"
```

### DNS Exfiltration and Tunneling

```python
# dnscat2 traffic reassembly
from scapy.all import rdpcap, DNSQR
packets = rdpcap('capture.pcap')
domain = '.skullseclabs.org.'
prev = None
data = b''
for p in packets:
    if not p.haslayer(DNSQR):
        continue
    qname = p[DNSQR].qname.decode()
    if domain not in qname:
        continue
    labels = qname.replace(domain, '').split('.')
    chunk = bytes.fromhex(''.join(labels))
    chunk = chunk[9:]  # strip 9-byte dnscat2 header
    if chunk == prev:
        continue  # skip retransmission
    prev = chunk
    data += chunk
with open('extracted.png', 'wb') as f:
    f.write(data)

# DNS binary oracle: NOERROR/NXDOMAIN as bit value
import dns.resolver
flag_bits = ""
for i in range(320):  # 40 bytes * 8
    for bit in ['0', '1']:
        try:
            dns.resolver.resolve(f"{flag_bits}{bit}.target.com", 'A')
            flag_bits += bit
            break
        except dns.resolver.NXDOMAIN:
            continue
```

### ICMP Covert Channels

```python
# Payload length encoding
from scapy.all import rdpcap, ICMP
pkts = rdpcap('capture.pcap')
flag = ''.join(
    chr(len(p[ICMP].payload))
    for p in pkts if ICMP in p and p[ICMP].type == 8
)
print(flag)

# Ping time-delay channel
from scapy.all import rdpcap, ICMP
pkts = rdpcap("capture.pcap")
pairs = {}
for p in pkts:
    if ICMP in p and p[ICMP].type == 8:
        pairs[p[ICMP].seq] = p.time
bits = []
for p in pkts:
    if ICMP in p and p[ICMP].type == 0:
        dt = p.time - pairs[p[ICMP].seq]
        if dt < 0.2:
            continue
        bits.append("1" if dt > 1.0 else "0")
data = int("".join(bits), 2).to_bytes(len(bits)//8, "big")
print(data)
```

### Split Archive Reassembly from HTTP

```bash
# Identify fragments: same-size files, one smaller trailer
# Order by Apache directory listing timestamps, not download order
cat file1 file2 file3 ... > archive.7z
# Find password from separate TCP conversation stream
tshark -r capture.pcap -q -z "follow,tcp,ascii,<stream>"
7z x archive.7z -p"password"
```

### Packet Interval Timing Encoding

```python
from scapy.all import rdpcap
packets = rdpcap('challenge.pcapng')
times = [float(pkt.time) for pkt in packets if pkt.sniffed_on == 'interface_2']
intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
threshold = 0.05  # 50ms distinguishes 10ms vs 100ms intervals
bits = [0 if dt < threshold else 1 for dt in intervals]
data = bytes(int(''.join(str(b) for b in bits[i:i+8]), 2)
             for i in range(0, len(bits) - 7, 8))
print(data.decode(errors='replace'))
```

### PCAP Repair

```bash
# Automatic repair (handles most corruption)
pcapfix -d corrupted.pcap

# Manual repair of magic bytes
python3 -c "
import struct
with open('corrupted.pcap', 'rb') as f:
    data = bytearray(f.read())
# Fix pcap magic (0xa1b2c3d4 = microsecond, 0xa1b23c4d = nanosecond)
data[0:4] = struct.pack('<I', 0xa1b2c3d4)
data[4:6] = struct.pack('<H', 2)  # version major
data[6:8] = struct.pack('<H', 4)  # version minor
with open('fixed.pcap', 'wb') as f:
    f.write(data)
"
```

### TFTP Netascii Decoding

```python
with open('file_raw', 'rb') as f:
    data = f.read()
data = data.replace(b'\r\n', b'\n').replace(b'\r\x00', b'\r')
with open('file_fixed', 'wb') as f:
    f.write(data)
```

### SMB3 Encrypted Traffic

```bash
# Extract NTLMv2 hash from SMB3 session
tshark -r capture.pcap -Y "ntlmssp.messagetype == 0x00000003" -T fields \
  -e ntlmssp.ntlmv2_response.ntproofstr

# Crack and derive session keys with Python Cryptodome
# hashcat -m 5600 for NTLMv2
```

### Timeroasting (MS-SNTP)

```bash
# Extract MS-SNTP hashes from NTP responses
tshark -r capture.pcapng -Y "ntp && ip.src == <DC_IP>" -T fields -e udp.payload

# Crack with hashcat mode 31300
hashcat -m 31300 -a 0 -O hashes.txt rockyou.txt --username
```

## Bypass

When PCAP is corrupted: use `pcapfix` for automatic repair, manually fix magic bytes and version fields. When TLS traffic cannot be decrypted: look for keylog files in artifacts, extract TLS master key from server coredump, factor weak RSA keys from certificates. When standard analysis tools miss data: check DNS query name last bytes, inspect ICMP payloads (often ignored), analyze inter-packet timing gaps, examine TCP flag combinations, check frames after IEND in JPEG streams. When data is in a non-standard encoding (BCD, netascii, byte-rotated), write custom decoders.

## Verification

Confirm by: flag string found in decrypted traffic, HTTP objects contain flag image/text, cracked credentials enable further access, covert channel decoded to readable message, extracted files are valid (ZIP, image, document), reassembled archive extracts correctly, XOR key decrypts payload.

## Pitfalls

Assuming TLS decryption with server RSA key works for ECDHE cipher suites (requires keylog file). Forgetting to check HTTP exported objects before deep packet inspection. Not checking for USB HID data in non-standard USB captures. Overlooking ICMP payloads that are dismissed as normal ping traffic. Not checking ALL TCP streams (stream 0 may be a red herring). Ignoring DNS query names as potential covert channel. Assuming PCAP plays a single trick (may have multiple layers: fake TLS + mDNS key + XOR + merge). Not checking WiFi for multiple key changes across the capture window. Forgetting timestamp ordering for split archive reassembly (not download order). TFTP netascii mode corrupts binary data if not corrected.
