# Security Research Workflow

## Trigger
Load when the agent is assigned a security research task against any target: bug bounty, penetration test, CTF challenge, or vulnerability assessment.

## Attack Surface
Any system with attackable interfaces — web applications, APIs, network services, mobile apps, cloud infrastructure.

## Decision Tree

```
START
  |
  v
[Phase 1: INTAKE] — Confirm scope and rules
  |-- Scope confirmed? --No--> Ask user, do not proceed
  v
[Phase 2: RECON] — Passive only. No packets to target.
  |-- Assets discovered? --No--> Broaden sources, try again
  v
[Phase 3: ENUM] — Active probing. Ports, services, fingerprints.
  |-- Live targets found? --No--> Report, exit or broaden scope
  v
[Phase 4: HUNT] — Exploit. Load playbooks, test systematically.
  |-- Finding confirmed? --No--> Rotate attack vector, loop
  v
[Phase 5: REPORT] — Document, verify, submit.
```

## Phase 1: Intake

**Required outputs before proceeding:**
- In-scope targets (domains, IP ranges, apps, endpoints)
- Out-of-scope restrictions
- Program rules (payout tier, safe harbor, testing headers)
- Timebox (6h / 24h / multi-day)

**Do not assume.** If any field is missing, ask the user.

## Phase 2: Recon (Passive)

**Rule: zero packets to target.** All data from third-party sources.

Sources (use 3+):
- Certificate Transparency logs (crt.sh, Censys)
- Wayback Machine / CommonCrawl historical snapshots
- GitHub dorks: `org:target password|api_key|SECRET|.env`
- Shodan / FOFA favicon hash search
- SecurityTrails / DNS history
- ASN / IP range mapping (bgp.he.net)

Output: asset inventory without touching the target.

## Phase 3: Enum (Active)

**Rule: now you may probe, but no exploit payloads yet.**

For each asset:
1. Port scan → identify open services
2. Service fingerprint → version, stack, framework
3. JS endpoint extraction → routes, API paths, hidden params
4. Directory enumeration → default paths, backups, config files

Output: live asset matrix: `domain → port → service → version → endpoint`

## Phase 4: Hunt (Exploit)

**For each candidate target:**
1. Match entry signal to attack playbook (see domain-specific modules)
2. Load the playbook — do not rely on memory
3. Select entry points (highest-value parameters first)
4. Execute payloads from the payload library
5. If blocked by WAF/IDS: load bypass toolkit
6. Capture evidence on every hit (HTTP trace, screenshot)

**Default attack order** (highest ROI first):
1. Auth bypass / privilege escalation
2. Injection (SQLi, SSTI, command)
3. SSRF / internal access
4. File read / path traversal
5. XSS / client-side
6. Business logic

## Phase 5: Report

For each confirmed finding:
1. Verify reproducibility (2+ independent attempts)
2. Document: title (≤80 chars), endpoint, vulnerability type
3. Reproduce: step-by-step with raw HTTP/cURL
4. Impact: CVSS 4.0 vector + business impact statement
5. Remediation: actionable fix, not generic advice

## Pitfalls
- Skipping recon and jumping straight to exploit payloads
- Testing out-of-scope assets discovered during recon
- Reporting without reproducible evidence
- Relying on memory for payloads instead of loading playbooks
