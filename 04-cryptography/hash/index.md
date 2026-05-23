# Hash Function Attacks

## Trigger

Load when a challenge involves: authentication tokens computed as `H(secret || message)` with MD5, SHA-1, or SHA-256; CRC32 used as a MAC; iterated hash chains for proof-of-work or time-lock puzzles; hash collisions enabling signature forgery; compression before encryption (CRIME-style oracles); or custom hash constructions using only XOR and rotations. Hash attacks exploit structural properties of the hash function itself rather than brute-forcing preimages.

## Attack Surface

Merkle-Damgard hash functions (MD5, SHA-1, SHA-256) are vulnerable to length extension: given `H(secret || msg)` and `len(secret)`, an attacker can compute `H(secret || msg || padding || extension)` without knowing the secret. This breaks any authentication scheme that uses `H(secret || message)` as a MAC. CRC32 is linear over GF(2), making it completely insecure as a MAC. Hash functions with collision-finding attacks (MD5, SHA-1) enable signature forgery when the protocol signs `sign(H(message))` instead of `sign(message)` directly. Truncated hash functions with small output spaces allow cycle detection for time reversal. XOR-aggregate hash verification (`XOR of H(files) == expected`) collapses to linear algebra over GF(2^256). Iterated hashing with variable iteration counts creates timing oracles when the iteration count depends on input.

## Decision Tree

First identify the hash construction. If the MAC is `H(secret || message)` with MD5, SHA-1, or SHA-256, attempt length extension using `hashpumpy` or `hlextend`. If the MAC uses CRC32, exploit its GF(2) linearity to forge arbitrary tags. If the challenge involves collision resistance, check whether the hash is MD5 or SHA-1 (both have practical collision attacks). If the hash is iterated many times (hash chains), check the output size -- truncated hashes (e.g., MD5 truncated to 64 bits) have short cycles that can be detected with Floyd's or Brent's algorithm. If hash outputs are XOR-combined for integrity verification, solve the linear system over GF(2). If the hash is a custom construction, classify its structure (ARX, XOR-only, sponge) and apply structural analysis: differential trails for ARX, GF(2) inversion for XOR-only, capacity check for sponges. If the hash uses only XOR and rotations, build the GF(2) transformation matrix and invert it. If the hash is used in a compression-then-encrypt scheme, measure ciphertext length as a side channel.

## Techniques

### Hash Length Extension

```python
import hashpumpy
new_hash, new_data = hashpumpy.hashpump(
    original_hash, original_data, append_data, secret_length
)
# new_data = original_data + padding + append_data
# new_hash = H(secret || new_data)
```

Works on Merkle-Damgard hashes (MD5, SHA-1, SHA-256). If the secret length is unknown, try lengths 1-32. HMAC is immune because it uses `H(K XOR opad || H(K XOR ipad || msg))`.

### Hash Length Extension with UTF-8 Filter Bypass

When the server rejects bytes >= 0x80, replace padding bytes with multi-byte UTF-8 sequences (e.g., `\xc2\x80` for 0x80) that the filter allows but the SHA-1 algorithm processes as the original bytes:

```python
import hlextend
h = hlextend.new('sha1')
forged = h.extend(b';cat flag', b'A' * msg_len, key_len, old_mac)
safe = forged.replace(b'\x80', b'\xc2\x80')
```

### Birthday Collision

```python
import os, hashlib
def birthday_collision(hash_fn, output_bits):
    target_bytes = output_bits // 8
    seen = {}
    while True:
        msg = os.urandom(16)
        h = hash_fn(msg).digest()[:target_bytes]
        if h in seen:
            return seen[h], msg
        seen[h] = msg
```

For n-bit output, expect collision after ~2^(n/2) attempts. 32-bit output needs ~65K tries.

### MD5 Multi-Collision via Fastcol

```bash
# Generate collision pair:
./fastcol -o suffix1A.bin suffix1B.bin < prefix.bin
# Chain: H(A||X) == H(A||Y) implies H(A||X||Z) == H(A||Y||Z)
# k collision pairs produce 2^k files with identical MD5
```

### SHA-1 Chosen-Prefix Collision for Signature Forgery

```bash
# Build two PDFs with different OCR output but identical SHA-1
./cpc prefix_A prefix_B collision_A.pdf collision_B.pdf
sha1sum collision_A.pdf collision_B.pdf  # identical
# Submit A for signature, replay on B
```

### CRC32 Linearity / Forgery

CRC is GF(2)-linear: `CRC(A XOR B) = CRC(A) XOR CRC(B) XOR C0` (where C0 is CRC of zeros):

```python
def crc_forge(data, target_crc):
    """Append 4 bytes to produce target CRC32 using polynomial division over GF(2)."""
    import binascii
    poly = 0xEDB88320  # reflected CRC-32 polynomial
    crc = target_crc ^ 0xFFFFFFFF  # invert final xor
    for b in data[::-1]:
        crc = _crc32_table_update(crc, b, poly)
    correction = crc ^ (binascii.crc32(data) & 0xFFFFFFFF)  # XOR: desired CRC xor current CRC
    return data + correction.to_bytes(4, 'little')

def _crc32_table_update(crc, byte, poly):
    crc ^= byte
    for _ in range(8):
        if crc & 1: crc = (crc >> 1) ^ poly
        else: crc >>= 1
    return crc

# When used with AES-CTR: flip plaintext bits, fix CRC simultaneously
X = b'\x00' * offset + b'\x01' + b'\x00' * remaining
crc_diff = binascii.crc32(X) ^ binascii.crc32(b'\x00' * len(X))
new_crc_ct = old_crc_ct ^ struct.pack('<I', crc_diff)
```

### Hash Chain Cycle Detection / Time Reversal

```python
def find_cycle(start, hash_fn):
    """Brent's algorithm: returns (cycle_length, start_offset)."""
    power = lam = 1
    tortoise = start
    hare = hash_fn(start)
    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power *= 2
            lam = 0
        hare = hash_fn(hare)
        lam += 1
    tortoise = hare = start
    for _ in range(lam): hare = hash_fn(hare)
    mu = 0
    while tortoise != hare:
        tortoise = hash_fn(tortoise)
        hare = hash_fn(hare)
        mu += 1
    return lam, mu

# Going "backward" N steps = going forward (cycle_length - N) steps
def time_reverse(state, target_step, current_step, cycle_len):
    forward = (cycle_len - (current_step - target_step)) % cycle_len
    for _ in range(forward):
        state = hash_fn(state)
    return state
```

### Compression Oracle (CRIME-style)

```python
baseline = len(oracle(""))
known = ""
for pos in range(secret_len):
    for c in string.printable:
        candidate = known + c
        length = len(oracle(candidate))
        if length <= baseline + len(known):  # compressed = match
            known += c
            break
```

When compression (zlib, LZW) is applied before encryption, matching input produces shorter ciphertext.

### SHA-256 Basis Attack on XOR-Aggregate Verification

```python
# When integrity check is XOR(sha256(files)) == expected
# Find 256 random files whose hashes form a GF(2) basis
from sage.all import GF, matrix
M = matrix(GF(2), [hash_to_bits(sha256(f)) for f in basis_files])
target = hash_to_bits(target_hash) ^ hash_to_bits(original_hash)
solution = M.solve_left(target)
# Include files where solution[i] == 1 in the final set
```

### Custom Hash State Reversal

When intermediate hash states are leaked, recover per-block inputs:

```python
def reverse_hash_states(states):
    blocks = []
    for i in range(len(states) - 1):
        # state_update: s(i+1) = ROR(s(i) ^ hash(block), 7)
        h = states[i] ^ ((states[i+1] << 7) | (states[i+1] >> 25)) & 0xFFFFFFFF
        blocks.append(h)
    return blocks
# Brute-force printable 4-byte blocks matching each hash value
```

### Custom Hash Structural Analysis

When a challenge implements a custom hash (non-standard ARX construction, custom compression function, or reduced-round variant), analyze its structure systematically:

```python
# Step 1: Classify the construction
# - ARX (Add-Rotate-XOR): non-linearity only from addition carries
# - XOR-only: fully GF(2)-linear -> invertible regardless of output size
# - Sponge: security depends on capacity (rate+capacity = state size)
# - Merkle-Damgard: vulnerable to length extension

# Step 2: Differential cryptanalysis for ARX
# Find high-probability differential trails through the round function
def find_arx_differential(round_fn, input_bits, output_diff, trials=2000):
    best = (0, None)
    for delta_in in range(1, min(1 << 16, 1 << input_bits)):
        matches = 0
        for _ in range(trials):
            x = randint(0, (1 << input_bits) - 1)
            y = round_fn(x) ^ round_fn(x ^ delta_in)
            if y == output_diff:
                matches += 1
        if matches > best[0]:
            best = (matches, delta_in)
    return best[1], best[0] / trials

# Step 3: Rotational cryptanalysis for ARX
# Check if f(x <<< r) == f(x) <<< r with significant probability
# If yes and rounds are few, full collision may be practical

# Step 4: Fixed point search
def find_fixed_points(hash_fn, bits, samples=100000):
    for _ in range(samples):
        x = randint(0, (1 << bits) - 1)
        if hash_fn(x) == x:
            return x
    return None

# Step 5: For reduced-round variants
# Fewer rounds -> lower diffusion -> differential/linear attack practical
# Compare to standard: < 50% of rounds -> expect practical collision
```

Key indicators: XOR-only hashes are GF(2)-linear and fully invertible; small-state sponge (capacity < 256 bit) admits algebraic state recovery; ARX with < 8 rounds for 32-bit word is vulnerable to differential attacks under 2^32 complexity; reused round constants leak structural information.

## Bypass

When length extension is blocked by HMAC or truncation, check if the hash is used elsewhere in a non-HMAC context. When CRC32 is used with a secret appended (`CRC(msg || secret)`), the linearity still enables forgery, but the attack must include the unknown secret length in the padding calculation. When a hash chain uses a truncated output, cycle detection becomes feasible for outputs as large as 80 bits (~2^40 time, ~2^40 space for 80-bit). When a server uses iterated SHA-256 with character-by-character comparison, timing differences from the additional iterations create a positional oracle. For sponge hash collision attacks, use meet-in-the-middle on the uncontrolled state bytes (rate smaller than capacity).

## Verification

For length extension, submit the forged message and MAC to the server and verify authentication succeeds. For collision attacks, confirm `hash(A) == hash(B)` and both messages are valid in the protocol. For CRC forgery, verify the forged tag passes the server's CRC check. For hash chain reversal, verify the recovered preimage satisfies the challenge condition. For basis attacks, verify that XORing the chosen files produces the target hash.

## Pitfalls

Applying length extension to HMAC (it does not work). Assuming length extension works on SHA-3/Keccak/SHAKE (it does not -- Keccak is a sponge, not Merkle-Damgard). Confusing big-endian and little-endian byte ordering in SHA-256 padding. Forgetting that length extension requires `len(secret) | len(original_message)` to compute the correct padding. Using CRC32 as a MAC when it provides zero integrity protection. Assuming hash collisions break the hash function completely (collision resistance is weaker than preimage resistance -- finding a collision does not imply finding a preimage). Overlooking that the compression oracle requires the secret to be in the same compression block as attacker-controlled data.
