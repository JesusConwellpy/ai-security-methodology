# Elliptic Curve Cryptography Attacks

## Trigger

Load when a challenge involves elliptic curve parameters `(a, b, p, G, Q)`, a pairing operation, ECDSA signatures, Ed25519 or EdDSA key material, or abstract groups presented as circle equations `(x^2 + y^2 = 1)` or clock groups. ECC challenges exploit misconfigured curves, reused randomness, or non-standard group structures.

## Attack Surface

The discrete logarithm problem (ECDLP) is the foundation of ECC security. It breaks when: the curve order has small prime factors (enabling Pohlig-Hellman); the curve is singular (discriminant is zero); the curve is anomalous (order equals field prime); point validation is skipped allowing invalid curve attacks; nonces in ECDSA are reused or biased; the curve uses a cofactor > 1 leading to torsion component leakage; or the group is not an elliptic curve at all but a structurally weak group like a circle group or singular variety.

## Decision Tree

Start by computing the curve discriminant `4a^3 + 27b^2 mod p`. If it is zero, the ECDLP reduces to the additive or multiplicative group of the field and is trivially solvable. If nonzero, check `E.order() == p` for Smart's attack (anomalous curve). If neither, factor the curve order: if it is smooth (all small prime factors), use Pohlig-Hellman to decompose the DLP into small subgroups and solve each independently with BSGS or Sage's `discrete_log`. If the challenge provides multiple ECDSA signatures, check for repeated `r` values (nonce reuse). If the challenge is on Ed25519 with a cofactor-related key derivation scheme, exploit the 8 torsion points. If the group is defined by `x^2 + y^2 = 1 mod p` (clock group), note the order is `p+1` and check if it is smooth. If none of these apply, check whether the generator or target point lies on a different curve with weaker security (invalid curve attack).

## Techniques

### Pohlig-Hellman on Smooth-Order Curves

```python
from sage.all import EllipticCurve, GF, discrete_log, factor
E = EllipticCurve(GF(p), [a, b])
n = E.order()
factors = factor(n)
G = E.gens()[0]
Q = E(Qx, Qy)
# Sage handles this automatically:
d = discrete_log(Q, G, ord=n, operation='+')
```

For manual decomposition when Sage's function is slow:

```python
partials, mods = [], []
for prime, exp in factors:
    pe = prime ** exp
    cof = n // pe
    G_sub = int(cof) * G
    Q_sub = int(cof) * Q
    d_sub = discrete_log(Q_sub, G_sub, ord=pe, operation='+')
    partials.append(d_sub)
    mods.append(pe)
d = crt(partials, mods)
```

### Smart's Attack on Anomalous Curves

When `E.order() == p`:

```python
# Sage handles this automatically in most versions
d = G.discrete_log(Q)

# Manual p-adic lift if Sage fails:
Qp = pAdicField(p, 2)
Ep = EllipticCurve(Qp, [a, b])
Gp = Ep.lift_x(ZZ(G[0]), all=True)
Qp_point = Ep.lift_x(ZZ(Q[0]), all=True)
for gp in Gp:
    for qp in Qp_point:
        try:
            pG = p * gp
            pQ = p * qp
            x_G = ZZ(pG[0]) / ZZ(pG[1]) / p
            x_Q = ZZ(pQ[0]) / ZZ(pQ[1]) / p
            secret = ZZ(x_Q / x_G) % p
            if int(secret) * E(G) == E(Q):
                print(f"Secret: {secret}")
        except: continue
```

### Singular Curve Attack

When discriminant is zero, find the singularity and map to a simple group:

```python
R.<x> = PolynomialRing(GF(p))
f = x^3 + a*x + b
df = f.derivative()
r = df.roots()[0][0]
# For cusp: map (x,y) -> (x-r)/y -> additive group GF(p)+
# For node: map (x-r)/(y) -> multiplicative group GF(p)*
# Then solve DLP in the simple group
```

### ECDSA Nonce Reuse

Two signatures sharing the same `r` value imply the same nonce `k` was used:

```python
n = curve_order
h1 = int(sha256(msg1).hexdigest(), 16)
h2 = int(sha256(msg2).hexdigest(), 16)
k = ((h1 - h2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n  # private key
```

This is the same class of bug that compromised the PlayStation 3 ECDSA signing key. Always check for repeated `r` values in any dataset of ECDSA signatures.

### DSA Limited k-Value Brute Force

When nonces are drawn from a small space (e.g., 1024 values):

```python
for k1 in range(1024):
    for k2 in range(1024):
        num = (s2 * k2 * h1 - s1 * k1 * h2) % q
        den = (s1 * k1 * r2 - s2 * k2 * r1) % q
        if den == 0: continue
        x = (num * pow(den, -1, q)) % q
        if pow(g, k1, p) % q == r1:
            print(f"Private key: {x}")
```

### Ed25519 Torsion Side Channel

When key is derived as `user_key = MASTER * uid mod l` with cofactor `h=8`:

```python
bits = []
for t in range(255):
    S_t = query_sign(3, 2**t)
    S_t1 = query_sign(3, 2**(t+1))
    doubled = point_double(S_t)
    # Torsion shift visible when wrap around l occurs
    bits.append(0 if doubled.y == S_t1.y else 1)
# MASTER_KEY ≈ l * (binary of bits), try 8 torsion corrections
```

### Clock Group DLP (x^2 + y^2 = 1 mod p)

The circle group has order `p+1` when `p ≡ 3 mod 4` (or `p-1` when `p ≡ 1 mod 4`), isomorphic to norm-1 elements of `GF(p^2)*`:

```python
def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # identity
    base = P
    while n > 0:
        if n & 1: result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result

# Recover hidden prime p from points on the curve:
from math import gcd
from functools import reduce
p = reduce(gcd, [x**2 + y**2 - 1 for x, y in known_points])
# Factor p+1; if smooth, Pohlig-Hellman applies
# Use p+1 when p ≡ 3 mod 4; use p-1 when p ≡ 1 mod 4
order = p + 1
```

### Invalid Curve Attack

When point validation is absent, send crafted points on a curve with small subgroup order:

```python
# Find a curve with small-order point sharing the same p
# The server computes scalar * crafted_point on the weak curve
# Leaks secret key bits modulo the small order
# Repeat with different small-order curves for full recovery via CRT
```

## Bypass

When the standard Pohlig-Hellman fails because the curve order is not smooth, check whether the generator has small order even if the curve order is large. For ECDSA nonce attacks, if nonces are not identical but are linearly related (e.g., `k2 = a * k1 + b`), solve the system of equations. If the server accepts user-supplied generators, provide a generator whose order divides the private key space. For the clock group, ensure you use order `p+1` not `p-1` (a common mistake). When the curve is not anomalous but has trace 2 (`E.order() = p - 1`), try the semismall subgroup attack or map to the multiplicative group.

## Verification

For ECDLP challenges, verify that `int(d) * G == Q`. For nonce reuse, verify that `k * G` produces the same `r` value. For signature forgeries, verify the forged signature passes the standard ECDSA verification equation. For the clock group, verify that the recovered exponent satisfies `clock_pow(G, d, p) == Q`. For singular curves, confirm the decoded flag is valid ASCII after mapping to the additive/multiplicative group.

## Pitfalls

Forgetting that Ed25519 scalars are reduced modulo `l` (the subgroup order), not the full curve order `8*l`. Mistaking the curve order `E.order()` for the subgroup order. Applying Pohlig-Hellman to the full order when only the generator's order matters (the generator may be in a smaller subgroup). Confusing the clock group order `p+1` with `p-1` or `p`. Using `inverse_mod` without checking that the value is coprime to the modulus. Assuming point compression preserves subgroup membership when it only preserves coordinates. Overlooking that singular curve DLP maps to the multiplicative group of the *extension field*, not the base prime field, for nodal singularities.
