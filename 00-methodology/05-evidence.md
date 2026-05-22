# Evidence Discipline

## Trigger
Load at Phase 5 (Report) to verify findings are reproducible and properly documented.

## Attack Surface
Not applicable — this is a process document for quality assurance.

## Decision Tree

```
Finding candidate
  |
  v
1. REPRODUCIBILITY: Can you trigger it twice independently?
  |-- YES → Capture HTTP trace for both attempts
  |-- NO → Mark as "unconfirmed hypothesis", do NOT report as finding
  |
  v
2. ISOLATION: Is the vulnerability real or a testing artifact?
  |-- Eliminate: your IP, test headers, cached responses
  |-- Verify from 2+ IPs/accounts if possible
  |
  v
3. MINIMAL REPRO: Strip payload to minimum needed
  |-- Remove unnecessary headers, cookies, params
  |-- Document the exact minimum request that triggers the bug
  |
  v
4. IMPACT VERIFICATION: What can actually be compromised?
  |-- Read? (file, DB row, config)
  |-- Write? (file, DB, cache)
  |-- Execute? (command, code, query)
  |-- Impersonate? (session, token, account)
  |
  v
5. SCOPE CHECK: Is this target in-scope?
  |-- YES → Proceed to report
  |-- NO → Stop, do not test further on this asset
```

## Evidence Requirements by Severity

| Severity | Minimum Evidence |
|----------|-----------------|
| Critical (9.0-10.0) | Raw HTTP request/response, screenshot, video, impact demo |
| High (7.0-8.9) | Raw HTTP request/response, screenshot |
| Medium (4.0-6.9) | Raw HTTP request/response |
| Low (0.1-3.9) | Request description + observed behavior |

## Anti-Hallucination Rules

1. Every payload in evidence must match a payload in the payload library — do not fabricate
2. Every HTTP response must be copy-pasted, not summarized from memory
3. Every impact claim must be verifiable: "I can read /etc/passwd" requires showing /etc/passwd
4. Unconfirmed = unconfirmed. Do not call a hypothesis a finding
5. One finding per report. Do not bundle unrelated issues

## HTTP Trace Capture

```
REQUEST:
POST /api/login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin'--","password":"x"}

RESPONSE:
HTTP/1.1 200 OK
Set-Cookie: session=eyJhZG1pbiI6dHJ1ZX0=...
{"role":"admin","message":"Welcome back"}
```

Always include: method, path, full headers relevant to the bug, request body, response status, response headers relevant to the bug, response body excerpt.

## Pitfalls
- Cached responses: a 200 from cache is not proof of exploitation
- Test artifacts: removing a test header may "fix" the bug
- Race conditions: a race that worked once may need 1000 attempts to trigger again
- Recording the wrong request/response pair and shipping fiction
