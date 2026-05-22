---
name: payload-reference
description: Security payload reference — SQL injection, XSS, SSRF, command injection, SSTI, file inclusion, JWT, deserialization, WAF bypass, binary exploitation, and post-exploitation payloads. Load specific payload files by category. NEVER generate payloads from memory — always reference this library.
license: MIT
compatibility: Requires filesystem-based agent with read access to the payloads directory.
allowed-tools: Bash Read Glob Grep
metadata:
  user-invocable: "true"
  argument-hint: "<payload-type>"
---

# Payload Reference

**Rule:** Payloads come from files, not from training memory. Before using any payload, read the corresponding file.

## Payload Index

| Category | Document | Lines |
|----------|----------|-------|
| SQLi, NoSQLi, XSS, RCE, SSRF, SSTI, LFI, XXE, JWT, GraphQL, deserialization, smuggling, upload, traversal, prototype pollution, WebSocket | [Web Payloads](../../payloads/web/index.md) | 1,348 |
| Buffer overflow, format string, shellcode, ROP chains, heap, kernel, seccomp | [Binary Payloads](../../payloads/binary/index.md) | 556 |
| Port scanning, SMB/AD/Kerberos, LLMNR, MITM, protocol attacks, tunneling, ADCS | [Network Payloads](../../payloads/network/index.md) | 491 |
| SQLi, XSS, RCE, SSRF, SSTI, LFI, JWT, Log4j, Spring, Fastjson, Struts2, WebLogic, ThinkPHP, Shiro, Tomcat, Laravel bypasses | [WAF Bypass](../../payloads/waf-bypass.md) | 736 |

## Usage

```
1. Identify attack type from target signal
2. Read the corresponding payload file
3. Select payload matching the target technology stack
4. If blocked, read WAF Bypass file for evasion variants
5. Document which payload worked and the target context
```

## Quick Lookup

```bash
# Search for payloads matching a specific technology
grep -i "mysql" payloads/web/index.md
grep -i "nginx" payloads/waf-bypass.md

# Find all payloads for a specific vulnerability class
grep -A5 "### SQL Injection" payloads/web/index.md
grep -A5 "### XSS" payloads/web/index.md
```
