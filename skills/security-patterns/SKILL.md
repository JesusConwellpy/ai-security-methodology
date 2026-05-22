---
name: security-patterns
description: Reusable attack patterns distilled from disclosed vulnerability reports. Use when hunting for vulnerabilities to understand common exploitation chains, or when you're stuck and need to think about what typically goes wrong in a given feature type.
license: MIT
compatibility: Requires filesystem-based agent with read access to the patterns directory.
allowed-tools: Bash Read Glob Grep
metadata:
  user-invocable: "true"
  argument-hint: "<pattern-category>"
---

# Attack Patterns

Distilled patterns from disclosed cases. Each pattern describes: what it is, signals to look for, typical exploitation flow, and generalized examples.

## Pattern Index

| Category | Document | Focus |
|----------|----------|-------|
| Password reset step-skip, SSO token theft, weak session keys, remember-me tokens | [Auth Vulnerabilities](../../patterns/auth-vulnerabilities.md) | Authentication flaws |
| Direct input concatenation, NoSQL operator injection, blind SQL, second-order injection | [Injection Patterns](../../patterns/injection-patterns.md) | Injection variants |
| Email verification bypass, unauthenticated API access, subscription manipulation, IDOR | [Authorization Bypass](../../patterns/authorization-bypass.md) | AuthZ bypass |
| Payment tampering, race conditions, password reset logic, CAPTCHA bypass, coupon abuse | [Business Logic Flaws](../../patterns/business-logic-flaws.md) | Logic flaws |
| Hop-by-hop header leakage, Alt-Svc credential leak, directory/file enumeration | [Information Disclosure](../../patterns/information-disclosure.md) | Info leaks |
| Unauthenticated endpoints, IDOR, BOLA, mass assignment, GraphQL introspection | [API Vulnerabilities](../../patterns/api-vulnerabilities.md) | API issues |
| Multi-step chains combining multiple low-severity issues into critical impact | [Chained Attacks](../../patterns/chained-attacks.md) | Attack chains |

## How to Use

```
1. Identify the feature type you're testing (auth, API, payment, file handling)
2. Load the corresponding pattern document
3. Check each pattern against the target: "Does our target have this signal?"
4. For each matching signal, follow the exploitation flow
5. Chain low-severity findings using chained-attacks patterns
```

## Reference Data

For vendor-specific fingerprints and default credentials (especially China-market enterprise software), load:
- [China Vendor Fingerprints](../../dictionaries/china-vendor-fingerprints.md)
- [Default Credentials](../../dictionaries/default-credentials.md)
