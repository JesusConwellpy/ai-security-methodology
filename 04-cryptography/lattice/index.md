# Lattice-Based Cryptography Attacks

## Trigger

Load when a challenge involves: many modular equations with a promise that hidden values are small, sparse, or close to each other; partial leakage of a secret nonce or state bits; high-bit or low-bit truncation of LCG states; a subset-sum or knapsack instance; vectors or matrices over `Z_q` where the true solution would be unusually short; noisy linear equations modulo `q`; or explicit mentions of LWE, Ring-LWE, NTRU, GGH, or "short vector." Lattice reduction is the universal tool for problems with a "small unknown" inside modular arithmetic.

## Attack Surface

The fundamental pattern is: a secret value `s` and known values `a_i` satisfy `a_i * s + e_i = b_i (mod q)` where each `e_i` is small. The equations can be stacked into a lattice where the short vector `(e_1, ..., e_n, s)` exists. LLL and BKZ find this short vector efficiently for moderate dimensions (up to ~300 for LLL, ~150 for BKZ with practical block sizes in CTFs). Specific manifestations: Hidden Number Problem (HNP) from ECDSA partial nonce leaks; truncated LCG output recovery; LWE secret and error recovery; subset-sum on knapsack cryptosystems; Merkle-Hellman cryptosystem; approximate GCD problems; and orthogonal lattice recovery for hidden binary matrices.

## Decision Tree

First identify what is "small" in the problem. Is the secret itself small (e.g., ternary coefficients in {-1,0,1})? Is the error vector small (LWE)? Are the unknown state bits small relative to the modulus (truncated LCG)? Is the nonce difference small (HNP)? Is the solution indicator binary (subset-sum)?

If the challenge involves ECDSA signatures with leaked nonce bits, formulate as HNP: `r_i * d - s_i * delta_i = s_i * leaked_i * 2^t - h_i (mod q)`. Build the lattice with `q` on the diagonal, the `s_i` coefficients, the RHS constants, and scaling factors. If the challenge involves LCG with truncated outputs, write `state_i = observed_i * 2^t + hidden_i` and reformulate the recurrence as a modular linear relation in the small `hidden_i`. If the challenge gives `A, b, q` with `b = A*s + e`, build the LWE embedding lattice. If the challenge asks to find binary `x_i` satisfying `sum(a_i * x_i) = target`, use the knapsack lattice. If the challenge involves moduli with a hidden common structure, try orthogonal lattice recovery.

## Techniques

### Hidden Number Problem (ECDSA Partial Nonce)

```python
from sage.all import Matrix, ZZ

def build_hnp_lattice(q, rs, ss, hs, leaked, t):
    n = len(rs)
    M = Matrix(ZZ, n + 2, n + 2)
    for i in range(n):
        M[i, i] = q
    for i in range(n):
        M[n, i] = ss[i]
        M[n + 1, i] = (hs[i] - ss[i] * leaked[i] * (1 << t)) % q
    M[n, n] = 1
    M[n + 1, n + 1] = q // (1 << t)
    return M

# Usage:
M = build_hnp_lattice(q, rs, ss, hs, leaked, t)
R = M.LLL()
# Inspect short rows for a plausible private key d
# Verify d against all signatures
```

The key insight: each signature contributes one row. The lattice distinguishes the correct `d` because it produces a vector much shorter than random. If one or two bits are off, brute-force the remaining uncertainty.

### Truncated LCG Recovery

When the LCG `x_{i+1} = a*x_i + b (mod m)` leaks only high bits `y_i = x_i >> t`:

```python
def build_truncated_lcg(m, a, b, ys, t):
    n = len(ys) - 1
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = m
    for i in range(n):
        rhs = (a * ys[i] * (1 << t) + b - ys[i + 1] * (1 << t)) % m
        M[n, i] = rhs
    M[n, n] = 1 << t
    return M

M = build_truncated_lcg(m, a, b, ys, t)
R = M.LLL()
# Recover hidden low bits z_i, reconstruct full states
```

### LWE via Embedding and CVP

```python
from sage.all import Matrix, ZZ, identity_matrix, block_matrix

def lwe_embedding(A, q):
    m, n = A.nrows(), A.ncols()
    top = block_matrix([[q * identity_matrix(m), Matrix(ZZ, m, n)]])
    bot = block_matrix([[A.transpose(), identity_matrix(n)]])
    return block_matrix([[top], [bot]])

# Reduce basis, then use Babai nearest plane
from fpylll import IntegerMatrix, LLL, CVP
# Build lattice basis, LLL reduce, then:
# closest = CVP.babai(B, target)
# Extract secret from last n components
# Project to {-1, 0, 1} for ternary secrets
```

### Subset-Sum / Knapsack

```python
def knapsack_lattice(weights, target):
    n = len(weights)
    M = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        M[i, i] = 1
        M[i, n] = weights[i]
    M[n, n] = -target
    return M

M = knapsack_lattice(weights, target)
R = M.LLL()
# Look for a row whose last coordinate is 0
# Remaining coordinates should be in {0, 1}
```

### Ring-LWE Flattening to Plain LWE

```python
def negacyclic_matrix(a_coeffs, n, q):
    """Flatten a(x) in Z_q[x]/(x^n+1) to rotation matrix."""
    rows = []
    for i in range(n):
        row = []
        for j in range(n):
            if j <= i:
                row.append(a_coeffs[i - j])
            else:
                row.append(-a_coeffs[n + i - j])
        rows.append(row)
    return Matrix(ZZ, rows)
# After flattening: b_vec = A_mat * s_vec + e_vec (mod q)
# Solve as plain LWE
```

### Merkle-Hellman Knapsack via LLL

```python
nbit = len(pubKey)
A = Matrix(ZZ, nbit + 1, nbit + 1)
for i in range(nbit):
    A[i, i] = 1
    A[i, nbit] = pubKey[i]
A[nbit, nbit] = -int(encoded)
res = A.LLL()
for row in res:
    if row[-1] == 0 and all(b in (0, 1) for b in row[:-1]):
        bits = list(row[:-1])
```

### Approximate GCD

```python
# Given h_i = f * p_i + n_i (flag * prime + noise)
M = matrix(ZZ, [
    [1, 0, 0, h1],
    [0, 1, 0, h2],
    [0, 0, 1, h3],
    [0, 0, 0, -1]
])
reduced = M.LLL()
# Short vector contains p1, p2, p3
# Recover f = (h1 - n1) / p1
```

### Orthogonal Lattice Recovery

```python
def orthogonal_lattice(H, M):
    """Recover hidden binary basis from h = alpha * A (mod M)."""
    k, n = H.nrows(), H.ncols()
    top = block_matrix([[M * identity_matrix(k), Matrix(ZZ, k, n)]])
    bot = block_matrix([[H.change_ring(ZZ).transpose(), identity_matrix(n)]])
    L = block_matrix([[top], [bot]])
    return L.LLL()
# Short rows in bottom-right block are orthogonal to hidden basis
```

## Bypass

When LLL almost works but not quite, try BKZ with block size 20-35: `M.BKZ(block_size=25)`. If the short vector has the right structure but incorrect sign, check both `+` and `-` orientations. If centering is wrong (values in `[0, q)` instead of `[-q/2, q/2]`), center them. If the lattice has too few equations, look for additional sources of constraints in the challenge (e.g., known flag prefix bytes). If the recovered secret is close but not exact, brute-force the last few bits. If rows and columns are swapped, transpose the matrix. If Babai's CVP gives poor results, try Kannan's embedding instead. For LWE with small modulus but large noise, verify the noise distribution is actually as promised (the challenge may have made the error smaller than specified).

## Verification

Check that the recovered secret satisfies the original equations. For HNP, verify `r*d - s*delta = h (mod q)` for each signature. For truncated LCG, verify the recurrence with recovered hidden bits. For LWE, compute `b - A*s (mod q)` and check the error is small. For knapsack, confirm `sum(weights[i] * bits[i]) == target`. For orthogonal lattices, verify the recovered vectors are orthogonal to the hidden basis.

## Pitfalls

Wrong scaling is the most common failure: one coordinate dominating the basis causes LLL to miss the short vector. Wrong centering: use `[-q/2, q/2]` not `[0, q)`. Wrong orientation: if the secret is a row vector, the lattice must be oriented accordingly. Too few samples: the lattice needs enough equations to constrain the secret. Noise too large: CTF LWE instances are intentionally below real hardness -- if your lattice fails, check parameter sizes, not the method. Forgetting brute-force finish: lattice reduction often gets "almost correct" and the last few bits need enumeration. Applying a lattice when the problem is actually plain linear algebra, CRT, or a simple encoding bug -- always try simpler methods first. Not checking whether `A` and `b` are already given over the integers (modular reduction may have been omitted by accident, making the problem trivial).
