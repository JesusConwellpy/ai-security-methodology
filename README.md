# AI Security Methodology

Security research methodology knowledge base designed for AI agent consumption. Covers vulnerability discovery, exploitation techniques, and defense analysis organized by attack type.

## Scope

- **Web security**: injection, auth bypass, SSRF, XSS, deserialization, HTTP smuggling, prototype pollution
- **Binary exploitation**: buffer overflow, format string, heap, ROP, kernel, sandbox escape
- **Reverse engineering**: static/dynamic analysis, anti-analysis, platform-specific patterns
- **Cryptography attacks**: RSA, ECC, symmetric ciphers, hash collisions, PRNG, lattice/LWE
- **Forensics**: disk, memory, network, steganography, side-channel analysis
- **AI/ML attacks**: prompt injection, adversarial ML, model extraction
- **Post-exploitation**: lateral movement, privilege escalation, Active Directory
- **Malware analysis**: static triaging, dynamic sandboxing, PE/.NET, C2 protocols
- **OSINT**: social media, geolocation, DNS/web reconnaissance

## Structure

```
00-methodology/       Core workflow and decision frameworks
01-web-attacks/       Web vulnerability techniques
02-binary-exploitation/  Binary exploitation techniques
03-reverse-engineering/  Reverse engineering techniques
04-cryptography/      Cryptography attack techniques
05-forensics/         Forensics analysis techniques
06-ai-ml/             AI/ML attack techniques
07-post-exploitation/ Post-exploitation and lateral movement
08-malware-analysis/  Malware analysis techniques
09-osint/             Open source intelligence
10-misc/              Miscellaneous techniques
payloads/             Payload library organized by target
patterns/             Reusable attack patterns from real-world cases
dictionaries/         Vendor fingerprints and default credentials
industry/             Industry-specific attack surfaces
references/           Tools index, compliance, and templates
```

## Document Format

Each technique document follows a uniform structure:

1. **Trigger** — when to load this knowledge
2. **Attack Surface** — target characteristics indicating this technique
3. **Decision Tree** — step-by-step diagnostic flow
4. **Techniques** — core methods with representative payloads
5. **Bypass** — detection/evasion approaches
6. **Verification** — how to confirm successful exploitation
7. **Pitfalls** — common mistakes and false positives

## Usage

Load relevant documents as context for AI agents performing security research tasks. Each document is self-contained and can act as a standalone skill module.
