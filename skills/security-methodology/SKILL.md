---
name: security-methodology
description: Security research methodology — 5-phase workflow (intake → recon → enum → hunt → report). Routes to specialized technique modules. Use when the user asks to audit, penetration test, bug bounty, find vulnerabilities, exploit a target, or perform any security assessment.
argument-hint: "<target or phase>"
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, and internet access.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch WebSearch
metadata:
  user-invocable: "true"
  argument-hint: "<target-or-phase>"
---

# Security Research Methodology

Orchestration skill for security research. Routes to specialized technique modules based on target characteristics and attack surface signals.

## Phase 1: Intake

Before any testing, confirm:
- In-scope targets (domains, IPs, endpoints)
- Out-of-scope restrictions
- Program rules (safe harbor, testing headers, payout tier)
- Timebox

**Do not assume.** If any field missing, ask.

## Phase 2: Recon (Passive)

Zero packets to target. Sources: crt.sh, Wayback, GitHub dorks, Shodan, SecurityTrails, ASN mapping.

→ Load [Passive Reconnaissance](00-methodology/01-recon-passive.md) for technique details.

## Phase 3: Enum (Active)

Port scan, service fingerprint, JS endpoint extraction, directory enumeration, virtual host discovery.

→ Load [Active Enumeration](00-methodology/02-enum-active.md) for technique details.
→ If China vendor systems detected (Seeyon, Tongda, Weaver, Yonyou, Kingdee): load [Vendor Fingerprints](dictionaries/china-vendor-fingerprints.md) and [Default Credentials](dictionaries/default-credentials.md).

## Phase 4: Hunt

Match entry signals to attack modules:

| Signal | Module | Primary Doc |
|--------|--------|-------------|
| HTTP/API/web app | `/web-attacks` | [Web Attacks Index](01-web-attacks/) |
| Binary/ELF/PE, remote service crash | `/binary-exploitation` | [Binary Index](02-binary-exploitation/) |
| Compiled binary, obfuscated code, firmware | `/reverse-engineering` | [Reverse Index](03-reverse-engineering/) |
| RSA/AES/ECC/PRNG, encrypted data | `/crypto-attacks` | [Crypto Index](04-cryptography/) |
| PCAP, disk image, memory dump, stego | `/forensics` | [Forensics Index](05-forensics/) |
| LLM agent, chatbot, ML model API | `/ai-ml-security` | [AI/ML Index](06-ai-ml/) |
| Shell obtained, internal network | `/post-exploitation` | [Post-Exploit Index](07-post-exploitation/) |
| Suspicious binary, C2 traffic, script | `/malware-analysis` | [Malware Index](08-malware-analysis/) |
| Public information gathering, social media | `/osint` | [OSINT Index](09-osint/) |
| Encoding puzzle, sandbox jail, RF/SDR signal | `/osint` | [Misc Index](10-misc/) |

**Payload discipline:** Load payloads from [Payload Library](payloads/) — do not generate from training memory.
**Bypass discipline:** If payloads are blocked, load [Bypass Toolkit](00-methodology/04-bypass-toolkit.md).

## Phase 5: Report

→ Load [Evidence Discipline](00-methodology/05-evidence.md) and [Reporting](00-methodology/06-reporting.md).
→ Check [Compliance](references/compliance.md) before submitting.

## When Stuck

- Don't know what to attack: [Attack Prioritization](00-methodology/03-attack-priority.md)
- Can't find vulnerabilities: [Control Gap Hunting](00-methodology/04-bypass-toolkit.md)
- Need real-world context: [Attack Patterns](patterns/)

## Priorities

- Auth bypass > Injection > SSRF > File read > XSS > Logic flaws
- Payloads from files, not from memory
- Evidence before conclusion: HTTP traces + screenshots
