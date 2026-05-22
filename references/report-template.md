# Security Assessment Report Template

A structured template for penetration testing and vulnerability assessment reports. Covers the complete report lifecycle from submission to remediation verification.

---

## Pre-Submission Checklist

- All confidential information redacted (passwords, tokens, keys)
- Proof of concept limited to demonstration (not full exploitation)
- Screenshots attached for every finding
- Reproduction steps tested and complete
- CVSS scores calculated correctly
- False positives eliminated
- Impact stated in business terms
- Remediation recommendations actionable
- References to CWE/CVE/OWASP where applicable
- Report spelling/grammar checked

---

## Report Title Format

```
[Severity] Vulnerability Type in [Component/Location]

Examples:
[Critical] SQL Injection in User Profile API
[High] Stored XSS in Customer Support Ticket System
[Medium] Missing Rate Limiting on Login Endpoint
[Low] Information Disclosure via Debug Endpoint
```

---

## Report Body Structure

### 1. Executive Summary

1-2 paragraphs describing the engagement scope and overall security posture.

| Severity | Count | Key Findings |
|----------|-------|--------------|
| Critical | # | List critical findings |
| High | # | List high severity findings |
| Medium | # | List medium severity findings |
| Low | # | List low severity findings |

### 2. Finding Detail Format

Each finding must include:
- **Classification**: CVSS v3.1 score, CWE, OWASP Top 10 mapping
- **Affected**: Specific URL, endpoint, or component
- **Status**: New / Verified / Fixed / Accepted Risk
- **Description**: Technical explanation with root cause analysis
- **Impact**: Business risk and attacker capabilities
- **Steps to Reproduce**: Numbered, actionable steps
- **Proof of Concept**: Request/response or payload
- **Remediation**: Specific, actionable fix recommendations
- **References**: CWE, CVE, OWASP links

### 3. Vulnerability Summary Table

```
| # | Severity | Finding | Component | CVSS | Status |
|---|----------|---------|-----------|------|--------|
| 1 | Critical | SQL Injection | /api/users | 9.8 | Verified |
| 2 | High | Broken Access Control | /admin/* | 7.5 | Verified |
```

---

## CVSS Quick Reference

### By Vulnerability Type

| Type | Typical Score |
|------|---------------|
| Unauthenticated RCE | 9.8 (Critical) |
| Unauthenticated SQLi | 9.8 (Critical) |
| Auth Bypass | 9.1 (Critical) |
| SSRF (metadata) | 7.5 (High) |
| Stored XSS | 5.4 (Medium) |
| Reflected XSS | 6.1 (Medium) |
| CSRF | 6.5 (Medium) |
| IDOR | 6.5 (Medium) |
| Information Disclosure | 4.3 (Medium) |
| Open Redirect | 4.7 (Medium) |
| Weak Password Policy | 6.5 (Medium) |

### CVSS v3.1 Metrics

- Attack Vector: Network / Adjacent / Local / Physical
- Attack Complexity: Low / High
- Privileges Required: None / Low / High
- User Interaction: None / Required
- Scope: Unchanged / Changed
- Confidentiality: None / Low / High
- Integrity: None / Low / High
- Availability: None / Low / High

---

## HackerOne Report Structure

```
# Summary
Brief 1-2 sentence summary

# Steps To Reproduce
1. Step one
2. Step two
3. Step three

# Supporting Material/References
Links, code, attachments

# Impact
Clear description of real-world impact
```

### H1 Severity Guide

| Rating | Criteria |
|--------|----------|
| Critical | Infrastructure compromise, full account takeover, mass data exfiltration |
| High | Significant control bypass, limited data exposure, privilege escalation |
| Medium | Information disclosure, CSRF on non-critical action, reflected XSS |
| Low | Missing security headers, minor info leak, directory listing |

---

## Bug Bounty Report Template

```
**Summary:** [One-line description]
**Severity:** [Critical/High/Medium/Low]
**Weakness:** [CWE category name]
**Affected:** [URL or endpoint]
**Description:** [Technical description]
**Steps to Reproduce:**
1. Prerequisite
2. Action
3. Result showing vulnerability
**Proof of Concept:** [Payload/Request/Code]
**Impact:** [What an attacker can achieve]
**Suggested Mitigation:** [How to fix]
**References:** [Links to CWE, documentation]
```

---

## Compensating Controls Assessment

| Control | Assessed | Notes |
|---------|----------|-------|
| WAF rule blocks exploit | Yes/No | Tested bypass variants |
| Network segmentation limits | Yes/No | Scope of exposure |
| Monitoring detects attack | Yes/No | Alert fidelity |
| Least privilege applied | Yes/No | Account restrictions |

### Risk Acceptance

- Finding: [Name]
- Accepted by: [Name/Role]
- Date: [Date]
- Planned fix: [Date]
- Compensating controls: [Description]

---

## Post-Remediation Verification

| Finding | Original Status | Fix Applied | Retest Date | Result |
|---------|----------------|-------------|-------------|--------|
| #1 | Verified | [Description] | [Date] | Fixed |
| #2 | Verified | [Description] | [Date] | Not Fixed |

Verification checklist:
- Re-executed original attack steps
- Tested bypass variants (encoding, case, methods)
- Verified no regression in adjacent functionality
- Screenshot captured of verification result
