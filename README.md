# AI Security Methodology

> Security research methodology for AI agents — attack patterns, decision trees, techniques, and payloads organized by vulnerability type.

83 self-contained technique documents across 16 modules. Each document follows a uniform AI-oriented structure: trigger conditions, attack surface identification, decision trees, core techniques with real payloads, bypass strategies, verification methods, and common pitfalls.

---

## Modules

| # | Module | Documents | Focus |
|---|--------|-----------|-------|
| 00 | [Methodology](00-methodology/) | 7 | Workflow, recon, enum, prioritization, bypass toolkit, evidence, reporting |
| 01 | [Web Attacks](01-web-attacks/) | 19 | SQLi, XSS, SSRF, SSTI, XXE, command injection, file upload, path traversal, deserialization, JWT, OAuth/SAML, prototype pollution, HTTP smuggling, GraphQL, race conditions, logic flaws, info disclosure, client-side, NoSQL injection |
| 02 | [Binary Exploitation](02-binary-exploitation/) | 7 | Buffer overflow, format string, heap, ROP, kernel, sandbox escape, shellcode |
| 03 | [Reverse Engineering](03-reverse-engineering/) | 5 | Static analysis, dynamic analysis, anti-analysis, languages & platforms, tools |
| 04 | [Cryptography](04-cryptography/) | 6 | RSA, ECC, symmetric ciphers, hash, PRNG, lattice/LWE |
| 05 | [Forensics](05-forensics/) | 5 | Disk, memory, network, steganography, side-channel |
| 06 | [AI/ML Attacks](06-ai-ml/) | 3 | Prompt injection, adversarial ML, model attacks |
| 07 | [Post-Exploitation](07-post-exploitation/) | 3 | Lateral movement, privilege escalation, Active Directory |
| 08 | [Malware Analysis](08-malware-analysis/) | 4 | Static triaging, dynamic sandboxing, PE/.NET, C2 protocols |
| 09 | [OSINT](09-osint/) | 3 | Social media, geolocation, DNS/web reconnaissance |
| 10 | [Misc](10-misc/) | 3 | Sandbox jails, encodings, RF/SDR |
| — | [Payloads](payloads/) | 4 | Web, binary, network payloads; WAF bypass variants |
| — | [patterns](patterns/) | 7 | Reusable attack patterns from disclosed cases |
| — | [Dictionaries](dictionaries/) | 2 | Vendor fingerprints, default credentials |
| — | [Industry](industry/) | 2 | Banking/finance and telecom attack surfaces |
| — | [References](references/) | 3 | Tools index, compliance, report template |

## Document Format

Every technique document is structured for AI agent consumption:

```
## Trigger        — When to load this knowledge
## Attack Surface — Target characteristics indicating this technique
## Decision Tree  — Step-by-step diagnostic flow
## Techniques     — Core methods with functional code and payloads
## Bypass         — Filter/WAF/IDS evasion strategies
## Verification   — How to confirm successful exploitation
## Pitfalls       — Common mistakes and false positives
```

## Skills

12 Claude Code skill definitions in [`skills/`](skills/) route AI agents to the right documentation based on attack surface signals:

| Skill | Trigger |
|-------|---------|
| [security-methodology](skills/security-methodology/SKILL.md) | Any security assessment or penetration test |
| [web-attacks](skills/web-attacks/SKILL.md) | HTTP application, API, browser client |
| [binary-exploitation](skills/binary-exploitation/SKILL.md) | Native binary, memory corruption |
| [reverse-engineering](skills/reverse-engineering/SKILL.md) | Compiled binary, obfuscated code, firmware |
| [crypto-attacks](skills/crypto-attacks/SKILL.md) | RSA, ECC, AES, hash, PRNG |
| [forensics](skills/forensics/SKILL.md) | Disk image, memory dump, PCAP, stego |
| [ai-ml-security](skills/ai-ml-security/SKILL.md) | LLM agent, chatbot, ML model API |
| [post-exploitation](skills/post-exploitation/SKILL.md) | Shell access obtained, internal network |
| [malware-analysis](skills/malware-analysis/SKILL.md) | Suspicious binary, script, C2 traffic |
| [osint](skills/osint/SKILL.md) | Public information gathering |
| [payload-reference](skills/payload-reference/SKILL.md) | Payload lookup (anti-hallucination) |
| [security-patterns](skills/security-patterns/SKILL.md) | Attack patterns and vendor fingerprints |

Each skill includes trigger conditions, a signal-to-document routing table, quick-start commands, and tool recommendations.

## Usage

Load relevant documents as context for AI agents performing security research. Each document is self-contained — read it, follow the decision tree, apply the techniques.

## License

MIT — see [LICENSE](LICENSE)
