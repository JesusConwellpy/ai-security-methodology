# Vulnerability Reporting

## Trigger
Load at Phase 5 when a finding has been verified and needs to be documented for submission.

## Attack Surface
Not applicable — process document for report generation.

## Report Structure

### Title (≤80 characters)

Formula: `[Vulnerability Type] in [Component] at [Endpoint] allows [Impact]`

Example: `SQL Injection in Login API at /api/auth/login allows Database Exfiltration`

### CVSS 4.0 Vector

Calculate using CVSS 4.0, not 3.1. Key differences:
- Attack Requirements (AT): None (N) or Present (P) — is user interaction or specific state needed?
- Subsequent System Impact: changed from binary to 3-level (Low/Medium/High)

Template:
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```
- AV: Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
- AC: Attack Complexity (L=Low, H=High)
- AT: Attack Requirements (N=None, P=Present)
- PR: Privileges Required (N=None, L=Low, H=High)
- UI: User Interaction (N=None, P=Passive, A=Active)
- VC/VI/VA: Vulnerable System (C=Confidentiality, I=Integrity, A=Availability)
- SC/SI/SA: Subsequent System impact

### Reproduction Steps

Each step must be executable by another person without guessing:

1. Send request to `POST /api/login` with body `{"username":"admin'--","password":"x"}`
2. Response returns admin session token
3. Use token to access `GET /api/admin/users` — returns full user list

Include raw HTTP for each step. Use cURL format for portability.

### Impact Statement

Describe business impact, not just technical effect:
- "Can read /etc/passwd" → "Can read server configuration files, enabling further attacks"
- "Database dump" → "All user PII, password hashes, and payment data exposed"
- "Admin account takeover" → "Attacker can modify/delete any user data, process refunds, export customer database"

### Remediation

Specific, actionable, not generic:
- Bad: "Sanitize input"
- Good: "Use parameterized queries (PDO prepared statements) for the `username` parameter in `LoginController.authenticate()`"
- Bad: "Update the framework"
- Good: "Upgrade Spring Boot from 2.5.0 to 2.5.13 to patch CVE-2022-22965"

## Severity Calibration

| Impact | Example |
|--------|---------|
| Critical | RCE, full DB read, auth bypass to any account, SSRF to cloud metadata |
| High | SQLi with partial data read, stored XSS, IDOR on sensitive data |
| Medium | Reflected XSS, path traversal to non-sensitive files, CSRF on state change |
| Low | Information disclosure (stack traces, server version), missing security headers |
| None | Warnings, best-practice deviations without exploit path |

## Pitfalls
- Inflating severity to make the finding seem more important
- Generic remediation advice that the engineering team cannot act on
- Missing the CVSS 4.0 vector (reduces credibility with triage teams)
- Bundling multiple distinct findings into one report
