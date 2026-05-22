# Symmetric Cryptography Attacks

## Trigger

Load when a challenge involves AES (any mode), block cipher encryption/decryption oracles, padding validation endpoints, GCM nonce reuse, stream cipher keystream reuse, custom substitution-permutation networks, or MAC verification with linear properties. Symmetric cryptography attacks exploit mode weaknesses, implementation flaws, or structural properties of the cipher.

## Attack Surface

Block cipher modes have distinct vulnerability signatures: ECB produces identical ciphertext blocks for identical plaintext blocks (detectable by repeating 16-byte patterns); CBC is vulnerable to padding oracle attacks and bit-flipping in the previous block when no MAC is used; CTR produces keystream that, if reused across messages, cancels the plaintext difference; GCM is catastrophically broken on nonce reuse (both confidentiality and authenticity fail); CFB with 8-bit feedback allows state reconstruction from known plaintext. Stream ciphers (RC4, LFSR, custom XOR constructions) are vulnerable to known-plaintext keystream recovery and, when the same key is reused, many-time pad attacks.

## Decision Tree

First, determine the cipher mode. If blocks are 16 bytes and identical blocks exist in the ciphertext, suspect ECB. If an IV is provided alongside the ciphertext, suspect CBC or CTR. If the challenge includes a nonce and authentication tag, suspect GCM. If a server returns distinguishable error messages for invalid padding, the challenge is a padding oracle. If encryption produces output the same length as input with no IV, suspect a stream cipher. If multiple ciphertexts share the same apparent structure (same length, same prefix), check for keystream reuse. If the challenge includes a custom cipher with a substitution box, check if the S-box is a permutation (non-permutation S-boxes enable collision attacks). If the challenge involves MAC verification, check if the MAC is computed using XOR-linear operations (CRC, custom constructions). For GCM, always look for repeated nonces across ciphertexts.

## Techniques

### Padding Oracle Attack (CBC)

```python
def padding_oracle(iv, ct):
    resp = requests.post(URL, data={'iv': iv.hex(), 'ct': ct.hex()})
    return 'invalid padding' not in resp.text

def decrypt_block(prev, target):
    intermediate = bytearray(16)
    for pos in range(15, -1, -1):
        pad = 16 - pos
        crafted = bytearray(16)
        for k in range(pos + 1, 16):
            crafted[k] = intermediate[k] ^ pad
        for guess in range(256):
            crafted[pos] = guess
            if padding_oracle(bytes(crafted), target):
                intermediate[pos] = guess ^ pad
                break
    return bytes(i ^ p for i, p in zip(intermediate, prev))
```

At most 4096 queries per block. Tools: PadBuster, `padding-oracle` pip package.

### ECB Byte-at-a-Time Chosen Plaintext

```python
known = b''
for i in range(len(secret)):
    pad_len = 15 - (len(known) % 16)
    pad = b'A' * pad_len
    target_ct = oracle(pad)
    block_idx = (pad_len + len(known)) // 16
    target_block = target_ct[block_idx*16:(block_idx+1)*16]
    for byte_val in range(256):
        test = pad + known + bytes([byte_val])
        if oracle(test)[block_idx*16:(block_idx+1)*16] == target_block:
            known += bytes([byte_val])
            break
```

### AES-GCM Nonce Reuse (Forbidden Attack)

```python
# Same nonce -> same CTR keystream
keystream = xor(known_plaintext, ciphertext1)
plaintext2 = xor(keystream, ciphertext2)

# GHASH auth key recovery from two tags with same nonce
# Construct polynomial in GF(2^128): T1 XOR T2 = P(H)
# Factor P(H) = 0 to recover H, then forge arbitrary tags
```

### CBC Bit-Flipping

```python
# P_{n+1} = AES_dec(C_{n+1}) XOR C_n
# Flipping bit i in C_n flips bit i in P_{n+1}
buf = bytearray(cookie)
offset = 10  # byte offset of target '0' in plaintext block n+1
buf[offset] ^= ord('0') ^ ord('1')  # changes '0' to '1' in P_{n+1}
forged = bytes(buf)
```

The preceding plaintext block will be garbled (random garbage), so the server must tolerate corruption in that field.

### AES-CTR Constant Counter / Keystream Reuse

```python
# When counter is constant, CTR = repeating 16-byte XOR key
for i, ct_byte in enumerate(ciphertext):
    pt_byte = ct_byte ^ keystream[i % 16]
```

Recover keystream from known file format headers or known plaintext prefixes.

### Non-Permutation S-Box Collision Attack

```python
sbox = [...]
if len(set(sbox)) < 256:
    # Find colliding pair
    for val, cnt in Counter(sbox).items():
        if cnt > 1:
            idx = [i for i in range(256) if sbox[i] == val]
            delta = idx[0] ^ idx[1]
    # For each key byte position, probe 256 plaintext pairs
    # When ct1 == ct2, S-box input is in collision set
    # 2-way ambiguity per byte -> 2^16 brute-force
```

### Ascon-like Reduced-Round Differential Cryptanalysis

```python
# For 4-round Ascon with reduced diffusion:
# Invert linear layer via GF(2) matrix
def invert_linear(shifts=(19, 28)):
    M = [[0]*64 for _ in range(64)]
    for out in range(64):
        M[out][out] = 1
        for s in shifts:
            M[out][(out + s) % 64] ^= 1
    # Gaussian elimination to invert
    aug = [row + [1 if i == j else 0 for j in range(64)] for i, row in enumerate(M)]
    for col in range(64):
        pivot = next(r for r in range(col, 64) if aug[r][col])
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(64):
            if r != col and aug[r][col]:
                aug[r] = [a ^ b for a, b in zip(aug[r], aug[col])]
    return [row[64:] for row in aug]

# Measure differential biases for chosen input differences
# Key bits classified via centroid clustering in 2D bias space
```

### Square (Integral) Attack on 4-Round AES

```python
# Choose 256 plaintexts with one byte iterating 0..255, others constant
# After 3 rounds, XOR sum at any byte position = 0 (balanced property)
for candidate in range(256):
    xor_sum = 0
    for ct in ciphertexts:
        xor_sum ^= inv_sbox[ct[pos] ^ candidate]
    if xor_sum == 0:
        print(f"Key byte: {candidate}")
```

### LFSR Stream Cipher via Berlekamp-Massey

```python
from sage.all import berlekamp_massey, GF
keystream_bits = [...]  # from known plaintext XOR ciphertext
F = GF(2)
seq = [F(b) for b in keystream_bits]
poly = berlekamp_massey(seq)
# poly.degree() gives LFSR length; poly.coeffs() give feedback taps
```

### GF(2) Gaussian Elimination for Linear Hash/MAC

```python
import numpy as np
def solve_gf2(A, b):
    Aug = np.hstack([A, b.reshape(-1, 1)]) % 2
    m, n = A.shape; row = 0
    for col in range(n):
        pivot = next((r for r in range(row, m) if Aug[r, col]), None)
        if pivot is None: continue
        Aug[[row, pivot]] = Aug[[pivot, row]]
        for r in range(m):
            if r != row and Aug[r, col]: Aug[r] = (Aug[r] + Aug[row]) % 2
        row += 1
    if any(Aug[r, -1] for r in range(row, m)): return None
    x = np.zeros(n, dtype=np.uint8)
    for r, c in reversed([(r, c) for r, c in enumerate(range(n)) if r < m]):
        x[c] = Aug[r, -1] ^ sum(Aug[r, c2]*x[c2] for c2 in range(c+1, n)) % 2
    return x
```

## Bypass

When a padding oracle rejects all modifications, check if the server uses a fixed IV (CFB-8 mode) that can be reconstructed from 16 known bytes. For GCM with short nonces (1-4 bytes), brute-force all nonce values if the key is known. When CBC bit-flipping corrupts a previous block that must remain valid, extend the attack to the IV (flip IV bits to affect block 0 with zero side effects). When the encryption uses a custom SPN with seeded permutations, recover the seed from partially recovered key bytes to constrain the remaining S-box entries. For compression oracle attacks (CRIME/BREACH), the distinguisher is ciphertext length rather than padding validity.

## Verification

Confirm the attack by: decrypting the ciphertext to readable plaintext; verifying that a forged MAC matches the server's expected value; confirming that repeated ECB blocks correspond to repeated plaintext; checking that the padding oracle accepts the crafted ciphertext as valid; running the recovered key through the original encryption to confirm round-trip correctness.

## Pitfalls

Confusing nonce and IV -- GCM nonce reuse is catastrophic but CBC IV reuse only affects identical messages. Overlooking that CBC padding oracle attacks require the attacker to control both IV and ciphertext, or at least the penultimate block. Forgetting PKCS#7 padding in OFB-MAC forgery calculations. Using the wrong AES-GCM polynomial for GHASH over GF(2^128). Not checking if the S-box is a permutation before attempting structural cryptanalysis. Assuming CTR mode uses a random nonce when it may use a constant counter. Neglecting to account for bit ordering in LFSR implementations (MSB-first vs LSB-first, Fibonacci vs Galois).
