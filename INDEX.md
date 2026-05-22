# Index

## 00-methodology
- [Security Research Workflow](00-methodology/00-workflow.md) — 5-phase methodology: intake → recon → enum → hunt → report
- [Passive Reconnaissance](00-methodology/01-recon-passive.md) — CT logs, DNS history, wayback, GitHub dorks
- [Active Enumeration](00-methodology/02-enum-active.md) — Port scanning, service fingerprinting, endpoint discovery
- [Attack Prioritization](00-methodology/03-attack-priority.md) — Decision tree for selecting attack vectors
- [Bypass Toolkit](00-methodology/04-bypass-toolkit.md) — WAF/IDS/EDR evasion strategies
- [Evidence Discipline](00-methodology/05-evidence.md) — HTTP traces, screenshots, reproducibility standards
- [Reporting](00-methodology/06-reporting.md) — Vulnerability reports and CVSS 4.0

## 01-web-attacks
- [SQL Injection](01-web-attacks/sql-injection/index.md)
- [NoSQL Injection](01-web-attacks/nosql-injection/index.md)
- [Cross-Site Scripting](01-web-attacks/xss/index.md)
- [Server-Side Request Forgery](01-web-attacks/ssrf/index.md)
- [Server-Side Template Injection](01-web-attacks/ssti/index.md)
- [XML External Entity](01-web-attacks/xxe/index.md)
- [Command Injection](01-web-attacks/command-injection/index.md)
- [File Upload](01-web-attacks/file-upload/index.md)
- [Path Traversal](01-web-attacks/path-traversal/index.md)
- [Deserialization](01-web-attacks/deserialization/index.md)
- [JWT Attacks](01-web-attacks/auth-jwt/index.md)
- [OAuth / SAML](01-web-attacks/auth-oauth-saml/index.md)
- [Prototype Pollution](01-web-attacks/prototype-pollution/index.md)
- [Request Smuggling](01-web-attacks/http-smuggling/index.md)
- [GraphQL](01-web-attacks/graphql/index.md)
- [Race Conditions](01-web-attacks/race-conditions/index.md)
- [Business Logic Flaws](01-web-attacks/logic-flaws/index.md)
- [Information Disclosure](01-web-attacks/info-disclosure/index.md)
- [Client-Side Attacks](01-web-attacks/client-side/index.md)

## 02-binary-exploitation
- [Buffer Overflow](02-binary-exploitation/buffer-overflow/index.md)
- [Format String](02-binary-exploitation/format-string/index.md)
- [Heap Exploitation](02-binary-exploitation/heap/index.md)
- [ROP Techniques](02-binary-exploitation/rop/index.md)
- [Kernel Exploitation](02-binary-exploitation/kernel/index.md)
- [Sandbox Escape](02-binary-exploitation/sandbox-escape/index.md)
- [Shellcode](02-binary-exploitation/shellcode/index.md)

## 03-reverse-engineering
- [Static Analysis](03-reverse-engineering/static-analysis.md)
- [Dynamic Analysis](03-reverse-engineering/dynamic-analysis.md)
- [Anti-Analysis Countermeasures](03-reverse-engineering/anti-analysis.md)
- [Language & Platform Patterns](03-reverse-engineering/languages-platforms.md)
- [Tools Reference](03-reverse-engineering/tools.md)

## 04-cryptography
- [RSA Attacks](04-cryptography/rsa/index.md)
- [ECC Attacks](04-cryptography/ecc/index.md)
- [Symmetric Ciphers](04-cryptography/symmetric/index.md)
- [Hash Collisions](04-cryptography/hash/index.md)
- [PRNG Attacks](04-cryptography/prng/index.md)
- [Lattice & LWE](04-cryptography/lattice/index.md)

## 05-forensics
- [Disk Analysis](05-forensics/disk/index.md)
- [Memory Analysis](05-forensics/memory/index.md)
- [Network Forensics](05-forensics/network/index.md)
- [Steganography](05-forensics/steganography/index.md)
- [Side-Channel Analysis](05-forensics/side-channel/index.md)

## 06-ai-ml
- [Prompt Injection](06-ai-ml/prompt-injection/index.md)
- [Adversarial ML](06-ai-ml/adversarial-ml/index.md)
- [Model Attacks](06-ai-ml/model-attacks/index.md)

## 07-post-exploitation
- [Lateral Movement](07-post-exploitation/lateral-movement/index.md)
- [Privilege Escalation](07-post-exploitation/privilege-escalation/index.md)
- [Active Directory](07-post-exploitation/active-directory/index.md)

## 08-malware-analysis
- [Static Triaging](08-malware-analysis/static-triaging.md)
- [Dynamic Sandboxing](08-malware-analysis/dynamic-sandboxing.md)
- [PE / .NET Analysis](08-malware-analysis/pe-dotnet.md)
- [C2 Protocols](08-malware-analysis/c2-protocols.md)

## 09-osint
- [Social Media](09-osint/social-media.md)
- [Geolocation](09-osint/geolocation.md)
- [DNS & Web Recon](09-osint/dns-web.md)

## 10-misc
- [Sandbox Jails](10-misc/sandbox-jails.md)
- [Encodings](10-misc/encodings.md)
- [RF / SDR](10-misc/rf-sdr.md)

## payloads
- [Web Payloads](payloads/web/index.md)
- [Binary Payloads](payloads/binary/index.md)
- [Network Payloads](payloads/network/index.md)
- [WAF Bypass Variants](payloads/waf-bypass.md)

## patterns
- [Auth Vulnerabilities](patterns/auth-vulnerabilities.md)
- [Injection Patterns](patterns/injection-patterns.md)
- [Authorization Bypass](patterns/authorization-bypass.md)
- [Business Logic Flaws](patterns/business-logic-flaws.md)
- [Information Disclosure](patterns/information-disclosure.md)
- [API Vulnerabilities](patterns/api-vulnerabilities.md)
- [Chained Attacks](patterns/chained-attacks.md)

## dictionaries
- [China Vendor Fingerprints](dictionaries/china-vendor-fingerprints.md)
- [Default Credentials](dictionaries/default-credentials.md)

## industry
- [Banking & Finance](industry/banking-finance.md)
- [Telecom / ISP](industry/telecom-isp.md)

## references
- [Tools Index](references/tools-index.md)
- [Compliance](references/compliance.md)
- [Report Template](references/report-template.md)
