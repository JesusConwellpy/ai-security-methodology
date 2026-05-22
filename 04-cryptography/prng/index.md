# PRNG Attacks

## Trigger

Load when a challenge generates random values using Python's `random` module, Java's `Random`, C's `srand`/`rand`, JavaScript's `Math.random()`, a custom linear congruential generator (LCG), a Mersenne Twister, or any deterministic PRNG. Also load when encryption keys are derived from time-based seeds, truncated random outputs are observable, or a server exposes random values through any endpoint (password reset tokens, session IDs, game state, nonces).

## Attack Surface

Deterministic PRNGs are entirely predictable once their internal state is recovered. Python's `random` (MT19937) has 624 x 32-bit words of state; observing 624 consecutive 32-bit outputs is sufficient for full state recovery via untempering. Even partial outputs (floats, truncated values) can be reconstructed via GF(2) matrix methods or constraint solving. LCGs are invertible and parameter-recoverable from consecutive outputs. Time-based seeding collapses the keyspace to the number of seconds (or milliseconds) since epoch. Java's `Random` uses a 48-bit LCG where 16 bits are discarded, enabling meet-in-the-middle attacks. V8's `Math.random()` uses XorShift128+ with 128 bits of state, recoverable from as few as 5-10 consecutive outputs via Z3. Custom PRNGs built from only XOR, shifts, and rotations are linear over GF(2) and solvable by matrix inversion.

## Decision Tree

Identify the PRNG algorithm. If the outputs are Python integers in `[0, 2^32)`, recover the MT19937 state with `untemper`. If the outputs are Python `random.random()` floats, collect ~3360 samples and use a precomputed GF(2) matrix. If the outputs are from Java's `Random`, exploit the 48-bit LCG with 16-bit truncation. If the PRNG is seeded with `time(NULL)`, compute the seed from the file timestamp or connection time. If the outputs are from V8's `Math.random()`, use Z3 with `QF_BV` theory on the XorShift128+ transformation. If the outputs are from an LCG with known modulus, recover parameters from consecutive outputs. If the PRNG uses only XOR, shifts, and rotations, treat it as a GF(2) linear system and invert the transformation matrix. If the PRNG outputs are truncated to fewer bits, treat the hidden bits as unknowns and solve with lattice reduction or constraint propagation.

## Techniques

### MT19937 State Recovery (Full Outputs)

```python
def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    for _ in range(7):
        y ^= (y << 7) & 0x9d2c5680
    y ^= y >> 11
    y ^= y >> 22
    return y

state = [untemper(output) for output in 624_outputs]
r = random.Random()
r.setstate((3, tuple(state + [0]), None))
# Now r.predicts all future outputs
```

For 63-bit outputs from `random.randrange(2**63)` (2 MT outputs combined):

```python
from z3 import *
mt = [BitVec(f'mt_{i}', 32) for i in range(624)]
s = Solver()
for i, out in enumerate(observed_63bits):
    if 2*i + 1 >= 624: break
    y1 = mt[2*i]; y1 = y1 ^ LShR(y1, 11)
    y1 = y1 ^ ((y1 << 7) & 0x9d2c5680)
    y1 = y1 ^ ((y1 << 15) & 0xefc60000); y1 = y1 ^ LShR(y1, 18)
    y2 = mt[2*i+1]; y2 = y2 ^ LShR(y2, 11)
    y2 = y2 ^ ((y2 << 7) & 0x9d2c5680)
    y2 = y2 ^ ((y2 << 15) & 0xefc60000); y2 = y2 ^ LShR(y2, 18)
    s.add(Concat(Extract(31, 0, y1), Extract(31, 1, y2)) == out)
s.check()
```

### MT19937 State from random.random() Floats

`random.random()` returns 53-bit float using 2 MT outputs. Truncating `int(f * 256)` yields 8 bits per sample. The `not_random` library precomputes the GF(2) mapping from bits to state words. Collect ~3360+ float samples for recovery.

### LCG Parameter Recovery

```python
# Given consecutive outputs [s0, s1, s2, ...] from x_{n+1} = (a*x_n + c) mod m
# Recover m first via GCD of differences of differences:
from math import gcd
diffs = [s1 - s0, s2 - s1, s3 - s2]
diffs2 = [diffs[1]*diffs[0] - diffs[0]*diffs[0], diffs[2]*diffs[1] - diffs[1]*diffs[1]]
m = abs(gcd(diffs2[0], diffs2[1]))
# Then recover a and c:
a = (s2 - s1) * pow(s1 - s0, -1, m) % m
c = (s1 - a * s0) % m
```

### LCG Backward Stepping (Invertible)

```python
a_inv = pow(a, -1, m)
prev = (a_inv * (state - c)) % m
```

Every power-of-two-modulus LCG (Java, C standard) is invertible.

### Java LCG Seed Meet-in-the-Middle

Java's `Random` uses 48-bit seed, discarding lowest 16 bits in `nextInt(n)`:

```python
# Phase 1: enumerate 2^18 low-18-bit candidates matching known prefix
candidates = []
for low in range(1 << 18):
    if simulate(low)[:K] == known_prefix:
        candidates.append(low)
# Phase 2: extend each to 48 bits
for low in candidates:
    for high in range(1 << 30):
        seed = (high << 18) | low
        if simulate(seed) == full_known:
            print(f"Seed: {seed}")
```

### V8 XorShift128+ Recovery (Math.random)

V8's `Math.random()` uses XorShift128+ with a 64-value LIFO cache:

```python
# xs128p step:
def xs128p(s0, s1):
    s1 ^= (s1 << 23) & 0xFFFFFFFFFFFFFFFF
    s1 ^= (s1 >> 17) & 0xFFFFFFFFFFFFFFFF
    s1 ^= s0
    s1 ^= (s0 >> 26) & 0xFFFFFFFFFFFFFFFF
    return s1, s0, (s1 + s0) & 0xFFFFFFFFFFFFFFFF  # (new_s0, new_s1, output)

# Z3 solver for floor(C * Math.random()) observations:
from z3 import *
def sym_xs128p(s0, s1):
    s1_ = s1          # start with old s1
    s0_ = s0
    s1_ ^= (s1_ << 23)
    s1_ ^= LShR(s1_, 17)
    s1_ ^= s0_
    s1_ ^= LShR(s0_, 26)
    return s1_, s0_   # (mutated_s1, old_s0)

def to_double(v):
    bits = (v >> 12) | 0x3FF0000000000000
    import struct
    return struct.unpack('d', struct.pack('<Q', bits))[0] - 1.0

# Constrain floor(C * to_double(state0)) == observed_val for each output
# Reverse observation order (LIFO cache requires tac)
```

For backward stepping (predicting before observed sequence):

```python
def undo_rshift_xor(val, shift):
    result = val
    for _ in range(3):
        result = val ^ (result >> shift)
    return result & 0xFFFFFFFFFFFFFFFF

def undo_lshift_xor(val, shift):
    result = val
    for _ in range(3):
        result = val ^ ((result << shift) & 0xFFFFFFFFFFFFFFFF)
    return result & 0xFFFFFFFFFFFFFFFF

def reverse_step(s0, s1):
    old_s1 = s0
    known = (s1 ^ s0 ^ ((s0 >> 26) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
    x = undo_rshift_xor(known, 17)
    old_s0 = undo_lshift_xor(x, 23)
    return old_s0, old_s1
```

### C srand/rand Synchronization

```python
from ctypes import CDLL
from time import time
libc = CDLL('libc.so.6')
libc.srand(int(time()))
for i in range(16):
    val = libc.rand() & 0xff  # Match binary's truncation
```

Account for the binary's startup delay (try +1 or +2 seconds).

### GF(2) Matrix PRNG Seed Recovery

```python
def build_matrix(prng, seed_bits, out_bits):
    import numpy as np
    M = np.zeros((out_bits, seed_bits), dtype=np.uint8)
    for i in range(seed_bits):
        seed = 1 << (seed_bits - 1 - i)
        out = prng(seed)
        for j in range(out_bits):
            M[j, i] = (out >> (out_bits - 1 - j)) & 1
    return M

# Solve M * seed == output (mod 2) via Gaussian elimination
```

Works for any PRNG using only XOR, shifts, and rotations (no S-boxes, no addition).

### Cellular Automaton PRNG via Z3 (Rule 86)

```python
def RULE86(x, y, z):
    return Or(And(Not(x), Not(y), z), And(Not(x), y, Not(z)),
              And(x, Not(y), Not(z)), And(x, y, Not(z)))

s = Solver()
state = [Bool(f'b{i}') for i in range(256)]
for rnd in range(128):
    new = [RULE86(state[(i-1)%256], state[i], state[(i+1)%256]) for i in range(256)]
    state = new
for i, bit in enumerate(known_output):
    s.add(state[i] == (bit == 1))
s.check()
```

### Logistic Map Chaotic PRNG Seed Recovery

```python
def logistic(x, r=3.99): return r * x * (1 - x)

def decrypt(cipher_hex, seed):
    import struct
    ct = bytes.fromhex(cipher_hex)
    x = seed; stream = b""
    while len(stream) < len(ct):
        x = logistic(x)
        stream += struct.pack("<f", x)[-2:]
    return bytes(a ^ b for a, b in zip(ct, stream[:len(ct)]))
```

## Bypass

When you have fewer than 624 MT outputs, use constraint propagation through the MT recurrence. Two outputs at indices 0 and 227 are theoretically sufficient for seed recovery via brute-force on the 32-bit seed. When outputs are filtered or masked, use the hidden bit information as constraints in Z3. For LCG with unknown modulus, recover it from the GCD of output differences. For time-seeded PRNGs with millisecond precision, brute-force the millisecond offset (1000 candidates) rather than the full second. When the PRNG outputs are XOR-masked with a user-controllable value, the mask directly reveals the state. When the PRNG has a short period (detectable by repeated outputs after N steps), all future outputs are predictable without recovering the internal state.

## Verification

After state recovery, predict the next 5-10 PRNG outputs and verify they match the server's subsequent responses. For LCG recovery, use the recovered parameters to regenerate the entire sequence from the seed. For MT19937, set the state via `setstate()` and call `random.random()` to confirm matches. For V8 XorShift128+, generate outputs using the recovered state and compare against observed values.

## Pitfalls

Forgetting that MT19937 twists after 624 outputs -- the 625th output depends on the twisted state, not the untempered state. Confusing `randcrack.submit()` with 32-bit vs 64-bit values. Not reversing the observation order for V8's LIFO Math.random cache. Assuming Python 2 and Python 3 `random` produce the same sequence from the same seed (they do not -- the module was rewritten). Using the wrong `libc.so.6` for srand/rand (use the one from the challenge binary, not the system one). Forgetting that Java's `nextInt(n)` discards bits differently for non-power-of-two `n`. Overlooking `random.SystemRandom` or `os.urandom` which are cryptographically secure and not attackable via state recovery.
