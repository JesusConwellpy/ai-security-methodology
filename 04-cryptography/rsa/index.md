# RSA Cryptography Attacks

## Trigger

Load when any of the following are present in a challenge: a single RSA public key `(n, e)` and ciphertext; multiple ciphertexts sharing a modulus `n`; a decryption or padding oracle endpoint; partial key material (dp, dq, qinv from a leak); encrypted flags with padding metadata; signing oracles that refuse to sign the target message; or observable timing differences in decryption responses. RSA challenges are among the most common in cryptography CTFs and come in the widest variety of attack surfaces.

## Attack Surface

Textbook RSA is multiplicatively homomorphic — this is the single most important property to remember. The factorization of `n` is the fundamental secret; anything that leaks information about `p`, `q`, or `phi(n)` is a foothold. Specific vulnerability indicators: very small public exponent `e` (typically 3) with a short message; very large `e` (close to `n`) implying small private exponent `d`; multiple ciphertexts with the same `n` but different `e` values; repeated `r` values in signatures (nonce reuse); error messages distinguishing "bad padding" from "bad plaintext"; observable timing variation correlated with private key operations; and user-submitted RSA parameters with insufficient validation.

## Decision Tree

Examine `n`, `e`, and any provided ciphertexts. If `n` is small or has known factors, factor it directly (FactorDB, sympy.factorint). If `e` is very small (3), check whether `m^e < n` by taking the integer eth root. If `e` is very large (close to `n`), try Wiener's continued fraction attack for small `d` (bound: `d < N^0.25`). If Wiener fails but `d` is still expected small, try Boneh-Durfee lattice attack (extends bound to `d < N^0.292`). If multiple ciphertexts share the same `n` but different `e` values coprime to each other, apply the common modulus attack. If multiple ciphertexts exist with the same small `e` across different `n`, try Hastad's broadcast attack via CRT. If a decryption oracle distinguishes padding validity, apply Bleichenbacher or Manger. If a signing oracle refuses the target message, exploit multiplicative homomorphism to blind or factor the message. If `|p - q|` is small, apply Fermat factorization. If `p-1` is smooth, try Pollard's p-1. If provided with only the CRT exponents (dp, dq, qinv), enumerate small `k` to recover `p`. If partial key bits are known, use Coppersmith's small roots. If multiple public keys are present in a dataset, compute pairwise GCDs to find shared primes.

## Techniques

### Small Exponent / Cube Root

When `m^e < n`, the ciphertext is a direct eth power with no modular reduction:

```python
import gmpy2
m, exact = gmpy2.iroot(c, e)
if exact:
    print(bytes.fromhex(hex(int(m))[2:]))
```

### Common Modulus

Given two ciphertexts `c1 = m^e1 mod n` and `c2 = m^e2 mod n` with `gcd(e1, e2) = 1`:

```python
def common_modulus(c1, c2, e1, e2, n):
    from math import gcd
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    g, a, b = egcd(e1, e2)
    assert g == 1
    if a < 0: c1 = pow(c1, -1, n); a = -a
    if b < 0: c2 = pow(c2, -1, n); b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m
```

### Wiener's Attack (Small Private Exponent)

When `d < N^0.25`, compute convergents of `e/n`:

```python
def wiener(e, n):
    cf, convs = [], []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    h0, h1, k0, k1 = 0, 1, 1, 0
    for q in cf:
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        if k1 == 0: continue
        if (e * h1 - 1) % k1 != 0: continue
        phi = (e * h1 - 1) // k1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc >= 0:
            from math import isqrt
            t = isqrt(disc)
            if t * t == disc: return h1
    return None
```

### Hastad's Broadcast Attack

Same plaintext encrypted with the same small `e` across `e` different moduli:

```python
from functools import reduce
def hastad(cts, mods, e):
    N = reduce(lambda a, b: a * b, mods)
    result = 0
    for ct, mod in zip(cts, mods):
        Ni = N // mod
        result += ct * Ni * pow(Ni, -1, mod)
    me = result % N
    m, exact = gmpy2.iroot(me, e)
    return int(m) if exact else None
```

### Coppersmith for Partially Known Primes

When part of a prime is known and the unknown portion is small:

```python
# p = base + 10^k * x where x < N^0.25
R.<x> = PolynomialRing(Zmod(N))
f = x + (base * inverse_mod(10**k, N)) % N
roots = f.small_roots(X=2**70, beta=0.5)
if roots:
    p = base + 10**k * int(roots[0])
    q = N // p
```

### Franklin-Reiter Related Message Attack

When two ciphertexts encrypt `m + pad1` and `m + pad2` with `e = 3`:

```python
R.<X> = PolynomialRing(Zmod(n))
f1 = (X + pad1)^3 - c1
f2 = (X + pad2)^3 - c2
g = gcd(f1, f2)
# If gcd returns non-monic polynomial, divide through by the leading
# coefficient before extracting the constant term.
lc = g.lc()  # leading coefficient (may not be 1 over Zmod(n))
m = -g[0] / lc if lc != 1 else -g[0]
```

### Bleichenbacher / Manger Padding Oracle

When a server reveals whether PKCS#1 v1.5 padding is valid, or whether the first byte of OAEP-decrypted message is zero. Manger's attack requires approximately `2 * log2(k)` queries for a `k`-bit key, using iterative multiplication of the ciphertext by `f^e` and binary search on the plaintext range.

### RSA Signature Forgery via Homomorphism

When a signing oracle refuses to sign target `m` but signs factorable components:

```python
sig_a = oracle.sign(m // 2)
sig_b = oracle.sign(2)
forged = (sig_a * sig_b) % n
```

Multiply partial signatures since `(a*b)^d mod n = a^d * b^d mod n`. To bypass blacklists, factor the target message into allowed components.

### LSB / Parity Oracle

When an oracle reveals the least significant bit of decrypted plaintext:

```python
lower, upper = 0, n
c_current = c
for i in range(n.bit_length()):
    c_current = (c_current * pow(2, e, n)) % n
    lsb = oracle(c_current)
    if lsb == 1:
        lower = (upper + lower) // 2
    else:
        upper = (upper + lower) // 2
```

### Factoring from Multiple of phi(n)

Given any multiple of `phi(n)`, factor via Miller-Rabin square root technique:

```python
def factor_from_phi(n, phi_mult):
    from math import gcd
    import random
    s, d = 0, phi_mult
    while d % 2 == 0: s += 1; d //= 2
    for _ in range(100):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            prev = x; x = pow(x, 2, n)
            if x == n - 1: break
            if x == 1:
                p = gcd(prev - 1, n)
                if 1 < p < n: return p, n // p
```

### gcd(e, phi) > 1

When standard inversion fails, reduce the exponent:

```python
from math import gcd
g = gcd(e, phi_n)
e_prime = e // g
d_prime = pow(e_prime, -1, phi_n)
m_g = pow(c, d_prime, n)
m, exact = gmpy2.iroot(m_g, g)
if not exact:
    for k in range(10000):
        m, exact = gmpy2.iroot(m_g + k * n, g)
        if exact: break
```

### Batch GCD for Shared Primes

When multiple moduli share a common prime (faulty RNG):

```python
from math import gcd
from functools import reduce
product = reduce(lambda a, b: a * b, moduli)
for n in moduli:
    g = gcd(n, product // n)
    if 1 < g < n:
        p = g; q = n // p
```

### Boneh-Durfee Attack (Small d)

When `d < N^0.292` and `e ≈ N`, Boneh-Durfee extends Wiener's bound using Coppersmith's method on the bivariate polynomial `f(x,y) = x*(A + y) - 1 mod e` where `A = (N+1)//2`. A lattice is built from monomial shifts of `f`, reduced via LLL, and the short vector reveals `(x,y) = (d, phi(N) - (N+1))`:

```python
# Boneh-Durfee: recover d when d < N^0.292 (e ≈ N)
# SageMath lattice attack using Coppersmith / LLL
def boneh_durfee(N, e, delta=0.292, m=3):
    P.<x, y> = PolynomialRing(ZZ)
    A = (N + 1) // 2  # standard variable mapping for Coppersmith formulation
    # Mapping: f(x,y) = x*(A+y) - 1 ≡ 0 (mod e), where x = d and y = k*(p+q-1) - (N+1)
    f = x * (A + y) - 1                 # f ≡ 0 (mod e)
    X = int(N^delta); Y = int(N^0.5)

    # Shift polynomials: x^i * f^k * e^(m-k), y^j * f^k * e^(m-k)
    polys = []
    for k in range(m + 1):
        for i in range(m - k + 1):
            polys.append(e^(m - k) * x^i * f^k)
        for j in range(1, m - k + 1):
            polys.append(e^(m - k) * y^j * f^k)

    # Build lattice from coefficient vectors, scale by X^dx * Y^dy
    monos = sorted(set(m for p in polys for m in p.monomials()))
    M = matrix(ZZ, len(polys), len(monos))
    for i, p in enumerate(polys):
        for mono, coeff in p:
            M[i, monos.index(mono)] = coeff
    for j, mono in enumerate(monos):
        M[:, j] *= int(X^mono.degree(x)) * int(Y^mono.degree(y))

    B = M.LLL()

    # Algebraic recovery from short vector
    for row in B:
        P_red = sum(int(row[j] / (int(X^monos[j].degree(x)) *
                   int(Y^monos[j].degree(y)))) * monos[j]
                   for j in range(len(monos)))
        # Compute resultant in y, find integer root -> d
        if P_red.degree(x) > 0:
            pass  # full recovery in mimoo/RSA-and-LLL-attacks
    return None
```

For CTF use, load [mimoo/RSA-and-LLL-attacks](https://github.com/mimoo/RSA-and-LLL-attacks) which includes complete recovery logic. Tuning: `m=3, delta=0.275` for fast results; `m=5` for the full `d < N^0.292` bound.

## Bypass

When standard attacks fail: the modulus may be `p^2` (totient is `p*(p-1)`, not `(p-1)^2`) or `p^2*q` requiring correct per-prime-power totient. Composite `n` may have many small factors that make factorization trivial via sympy.factorint. For `gcd(e, phi) > 1`, take the eth root after partial decryption instead of inverting. When `p = q` (server accepts but miscomputes totient), the real totient is `p*(p-1)`. When a message is too large for the cube root, add `k * n` for increasing `k` (known plaintext length bounds the search). When partial key recovery fails, brute-force remaining unknown bits if the search space is small enough.

## Verification

For RSA challenges, always compute `pow(c, d, n)` and decode the result. Check if the output starts with a known flag prefix, is printable ASCII, or matches an expected format. For signature attacks, verify that `pow(forged_sig, e, n)` equals the padded message. For factorization, verify `p * q == n`. For oracle attacks, confirm the recovered plaintext decrypts the original ciphertext correctly.

## Pitfalls

Confusing `phi(n) = (p-1)*(q-1)` with `phi(p^k) = p^(k-1)*(p-1)` when `p = q`. Forgetting to handle negative exponents in common modulus via modular inverse. Using Wiener when `d > N^0.25` — it will fail silently. Applying Coppersmith without making the polynomial monic. Using `beta` incorrectly in `small_roots` (beta should match the exponent of the target factor). Off-by-one errors in LSB oracle binary search bounds. Assuming PKCS#1 v1.5 padding oracle needs the full 00 02 prefix check when Manger's attack only needs a single-byte comparison. Overlooking that RSA blinding requires the blinding factor to be coprime to `n`. Not checking if the challenge uses `e = 1` (trivial: ciphertext equals plaintext mod n).
