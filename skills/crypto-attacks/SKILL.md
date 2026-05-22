---
name: crypto-attacks
description: Cryptography attack techniques — RSA, ECC, symmetric ciphers, hash collisions, PRNG attacks, lattice/LWE. Use when the challenge involves encryption, decryption, key recovery, nonce reuse, padding oracles, or cryptanalysis of custom schemes.
license: MIT
compatibility: Requires filesystem-based agent with Python 3, SageMath, pycryptodome, and gmpy2.
allowed-tools: Bash Read Write Edit Glob Grep WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "<crypto-type or ciphertext>"
---

# Cryptography Attacks

## Triage

```python
# Check properties of provided parameters
n = ...  # modulus
e = ...  # public exponent
# Is n factorable? Check FactorDB, sympy.factorint
# Is e small (3)? Try integer root
# Is e large (close to n)? Try Wiener
# Multiple ciphertexts same n? Common modulus
# Multiple n values? Check gcd(n_i, n_j) for shared primes
```

## Document Map

| Signal | Document |
|--------|----------|
| RSA (n, e, c), textbook RSA, signature oracle | [RSA Attacks](04-cryptography/rsa/index.md) |
| ECC parameters, small subgroup, anomalous curve | [ECC Attacks](04-cryptography/ecc/index.md) |
| AES-CBC/CTR/GCM, padding oracle, nonce reuse | [Symmetric Ciphers](04-cryptography/symmetric/index.md) |
| MD5/SHA-1/SHA-256, hash extension, collisions | [Hash](04-cryptography/hash/index.md) |
| MT19937, LCG, XorShift, C rand(), Java Random | [PRNG Attacks](04-cryptography/prng/index.md) |
| Lattice reduction, LWE, HNP, knapsack, subset-sum | [Lattice & LWE](04-cryptography/lattice/index.md) |

## Common Attack Checklist

- [ ] Factor modulus (FactorDB, YAFU, sympy.factorint)
- [ ] Check for trivial small-e (cube root attack if m^e < n)
- [ ] Check for common modulus (same n, different e)
- [ ] Check for shared primes across multiple n values (batch GCD)
- [ ] Check CBC padding oracle if decryption oracle exists
- [ ] Check for nonce reuse in CTR/GCM
- [ ] Check for hash length extension if `H(secret || data)` pattern
- [ ] Check MT19937 predictability if any PRNG output is observed

## Quick Tools

```bash
# RSA
python -c "from Crypto.Util.number import *; print(long_to_bytes(int(gmpy2.iroot(c, e)[0])))"
# FactorDB lookup
curl -s "http://factordb.com/api?query=$n"
# Wiener attack
python -c "from owiener import attack; print(attack(e, n))"
```
