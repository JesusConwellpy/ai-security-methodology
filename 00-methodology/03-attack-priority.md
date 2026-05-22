# Attack Prioritization

## Trigger
Load when multiple attack vectors are available after enumeration. Determines which vulnerability class to test first.

## Decision Tree

```
Live asset matrix
  |
  v
1. AUTH: Does the target have login/registration?
  |-- YES → Test auth bypass, JWT, OAuth, session issues FIRST
  |      Why: Auth bypass = full access, highest impact
  |
  v
2. INJECTION: Does user input reach server-side processing?
  |-- SQL DB? → SQLi
  |-- Template engine? → SSTI
  |-- Shell command? → Command injection
  |-- Deserialization? → Object injection
  |-- XML parser? → XXE
  |      Why: Injection can lead to RCE, data exfiltration
  |
  v
3. SSRF: Do any endpoints fetch external URLs?
  |-- Webhook, import, proxy, image fetch → SSRF
  |      Why: SSRF can reach internal services, cloud metadata
  |
  v
4. FILE: File upload or path parameters?
  |-- Upload → File upload RCE
  |-- Path param → Path traversal / LFI
  |      Why: File read → source code → more vulns
  |
  v
5. CLIENT-SIDE: User input reflected in page?
  |-- HTML/JS context → XSS
  |-- Admin bot? → Stored XSS → account takeover
  |      Why: XSS is high-frequency, lower impact unless chained
  |
  v
6. LOGIC: Complex business flows?
  |-- Payment, checkout, password reset → Business logic
  |-- Race conditions on state-changing endpoints → TOCTOU
  |      Why: Logic bugs bypass all technical controls
```

## Priority Matrix

| Priority | Vulnerability Class | Typical Impact | Effort |
|----------|-------------------|----------------|--------|
| P0 | Auth bypass / privilege escalation | Full account takeover | Low-Medium |
| P1 | SQLi, Command Injection | RCE, data breach | Medium |
| P2 | SSRF | Internal network access | Medium |
| P3 | SSTI, Deserialization | RCE | Medium-High |
| P4 | Path Traversal, LFI | Source code disclosure | Low |
| P5 | File Upload RCE | Code execution | Medium |
| P6 | XXE | File read, SSRF | Low-Medium |
| P7 | XSS | Session theft | Low |
| P8 | Business Logic | Varies | High (analysis) |
| P9 | Information Disclosure | Recon data | Low |

## When Stuck

If no vulnerabilities are found with high-priority attacks:
1. Go back to enumeration — you missed something
2. Check for information disclosure (`.git`, `.env`, debug endpoints)
3. Try the "control gap" approach: map every user input to server action, find the unmatched one
4. Chain low-severity issues: info disclosure → credential → auth → high impact

## Pitfalls
- Spending hours on XSS when there's an unauthenticated SQLi endpoint
- Testing complex RCE chains when default credentials are available
- Following the same attack order blindly — adjust based on target specifics
