# Security Testing Compliance Reference

A reference for compliance-aware security testing. Defines boundaries, mandatory actions, and withdrawal criteria during penetration testing engagements.

---

## Absolute Prohibitions

The following actions are strictly prohibited during any security testing engagement:

```yaml
prohibited_actions:
  - description: "Unauthorized data destruction"
    details: "Deleting, corrupting, or encrypting production data"

  - description: "Unauthorized privilege escalation"
    details: "Creating persistent backdoors, adding unauthorized accounts"

  - description: "Social engineering against non-consenting personnel"
    details: "Phishing, vishing, physical social engineering without explicit scope"

  - description: "Denial of service without explicit authorization"
    details: "DoS/DDoS attacks, resource exhaustion testing"

  - description: "Modifying production configurations"
    details: "Changing firewall rules, routing, DNS records"

  - description: "Exfiltrating data beyond proof-of-concept"
    details: "Extracting minimum data needed to demonstrate impact"

  - description: "Attacking third-party systems without authorization"
    details: "Systems not owned by the client, not in scope"
```

---

## Mandatory Actions

```yaml
pre_engagement:
  - "Verify scope document matches authorized targets"
  - "Confirm escalation contacts and procedures"
  - "Establish communication channels (encrypted)"
  - "Document rules of engagement and test schedule"
  - "Acquire and verify authorization letters / penetration testing agreements"

during_engagement:
  - "Log all testing activities with timestamps"
  - "Take screenshots and capture evidence for every finding"
  - "Document unsuccessful attempts (negative results)"
  - "Report critical findings immediately to POC"
  - "Use isolated test accounts where possible"
  - "Back up any data before modification attempts"
  - "Verify scope continuously - report out-of-scope findings separately"

post_engagement:
  - "Remove all backdoors, shells, accounts"
  - "Restore modified configurations to original state"
  - "Securely destroy test data"
  - "Provide detailed report within agreed timeline"
  - "Participate in remediation verification"
```

---

## Withdrawal Triggers

Testing must be halted immediately when any of the following occur:

```yaml
technical_triggers:
  - "Unexpected service degradation or outage"
  - "Production system becomes unresponsive"
  - "Unexpected data corruption"
  - "Antivirus / EDR flags test activity causing incidents"
  - "Rate limiting impacts legitimate users"
  - "Account lockout policies affecting real users"

procedural_triggers:
  - "Scope change without proper authorization"
  - "Client requests halt"
  - "Legal or compliance concern arises"
  - "Unexpected third-party data exposure"
  - "Discovery of critical unpatched vulnerability affecting production"
```

---

## Testing Type Comparison

| Aspect | Black Box | White Box | Grey Box |
|--------|-----------|-----------|----------|
| Prior knowledge | None | Full source / architecture | Partial credentials / docs |
| Realism | Highest | Lower | Medium |
| Coverage | Lower | Highest | High |
| Time required | Longest | Shortest | Medium |
| Best for | External posture | Full audit | Targeted review |
| Typical depth | Shallow-to-moderate | Deep | Moderate-to-deep |

---

## CVSS Scoring Reference

### Quick-reference CVSS v3.1 scores by vulnerability type:

| Vulnerability Type | Typical CVSS | Justification |
|--------------------|-------------|---------------|
| RCE (unauthenticated) | 9.8 (Critical) | No auth, full compromise |
| SQL injection (unauthenticated) | 9.8 (Critical) | Data access, potential RCE |
| Authentication bypass | 9.1 (Critical) | Complete auth failure |
| Deserialization RCE | 9.8 (Critical) | Remote code execution |
| SSRF to cloud metadata | 8.8 (High) | Credential access |
| Stored XSS | 7.1 (High) | User interaction needed |
| Reflected XSS | 6.1 (Medium) | Requires user interaction |
| CSRF | 6.5 (Medium) | Requires user action |
| Information disclosure | 5.3 (Medium) | Read-only data access |
| Open redirect | 4.7 (Medium) | Limited direct impact |
| Missing HSTS header | 3.7 (Low) | MitM context required |
| Directory listing | 3.3 (Low) | Info gathering only |

---

## Common Compliance Frameworks

```yaml
frameworks:
  PCI DSS:
    description: "Payment Card Industry Data Security Standard"
    scope: "Any system processing cardholder data"
    testing_requirements:
      - "Annual penetration testing (internal + external)"
      - "Quarterly ASV scans"
      - "Network segmentation validation"
      - "Application layer penetration test (v3.2)"
      - "Code review for custom applications"
    notes: "Most prescriptive pentest framework"

  ISO 27001:
    description: "Information Security Management Standard"
    scope: "ISMS certified organizations"
    testing_requirements:
      - "Regular penetration testing (frequency defined by risk)"
      - "Vulnerability assessments"
      - "Controls effectiveness testing"
    notes: "Less prescriptive, risk-based approach"

  SOC 2:
    description: "Service Organization Control 2"
    scope: "Service providers handling customer data"
    testing_requirements:
      - "Penetration testing at least annually"
      - "Vulnerability scanning (quarterly)"
      - "Logical access testing"
    notes: "Type II requires evidence of continuous monitoring"

  NIST SP 800-115:
    description: "Technical Guide to Information Security Testing"
    scope: "US federal agencies"
    testing_requirements:
      - "Discovery, enumeration, vulnerability mapping"
      - "Exploitation and proof of concept"
      - "Post-exploitation and persistence analysis"
      - "Reporting with findings and remediation"
    notes: "Most comprehensive methodology guide"

  OWASP Testing Guide:
    description: "Web Application Security Testing"
    scope: "Web applications"
    testing_requirements:
      - "Information gathering"
      - "Configuration management testing"
      - "Authentication testing"
      - "Authorization testing"
      - "Session management testing"
      - "Input validation testing"
      - "Error handling testing"
      - "Business logic testing"
      - "Cryptography testing"
    notes: "Essential methodology for web testing"
```

---

## Responsible Disclosure Guidelines

```yaml
disclosure_process:
  step_1:
    action: "Report to vendor's security team"
    timeline: "Immediately upon discovery"
    method: "Encrypted email / bug bounty platform"
  
  step_2:
    action: "Provide detailed report with reproduction steps"
    timeline: "Within 24 hours of initial report"
    content: "Vulnerability description, impact, PoC, CVSS, remediation suggestion"
  
  step_3:
    action: "Acknowledge receipt and cooperate on timeline"
    timeline: "Vendor should acknowledge within 72 hours"
    
  step_4:
    action: "Coordinate disclosure date"
    timeline: "Standard: 90 days after vendor acknowledgment"
    exceptions: "Critical vulnerabilities may warrant shorter timeline"
  
  step_5:
    action: "Public disclosure (if needed)"
    timeline: "After patch release or 90-day window expires"
    notes: "Coordinate with vendor, include mitigation guidance"
```

---

## Bug Bounty Platform Nuances

```yaml
hackerone:
  - "Always check program scope and out-of-scope list"
  - "Use the built-in report template for optimal triage"
  - "Include clear reproduction steps and impact"
  - "Rate limiting / DoS-lite typically out of scope"
  - "Automated scanning may be prohibited"
  - "Disclosure: most programs are private by default"

bugcrowd:
  - "Similar process to HackerOne"
  - "VRT (Vulnerability Rating Taxonomy) determines payouts"
  - "Priority ratings affect payout tiers"
  - "Safe harbor typically provided"

intigriti:
  - "European platform"
  - "Strong mediation process"
  - "Quarterly researcher leaderboards"

local_platforms:
  china:
    - "补天平台 (butian.net) - Qi-Anxin"
    - "漏洞盒子 (loudong.360.cn)"
    - "CNVD - Chinese National Vulnerability Database"
    - "CNNVD - Chinese National Vulnerability Database"
```

---

## Report Quality Standards

### Minimum Requirements

```yaml
each_finding_must_include:
  - "Title: Clear, standardized vulnerability name"
  - "Severity: CVSS v3.1 score and rating"
  - "Affected: Specific URL, endpoint, component"
  - "Description: Technical explanation of the vulnerability"
  - "Impact: Business risk and exploitation scenarios"
  - "Reproduction: Step-by-step instructions with screenshots"
  - "Payload: Exact request/response or code used"
  - "Remediation: Specific fix recommendations"
  - "References: CWE, CVE, OWASP mappings"
```

### Sample Finding Structure

```markdown
## [CRITICAL] SQL Injection in /api/user endpoint

**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-89 (SQL Injection)
**Affected:** https://target.com/api/user?id=1

### Description
The `id` parameter in `/api/user` is directly concatenated into SQL query without parameterization, allowing arbitrary SQL command execution.

### Impact
- Full database access
- Potential RCE via xp_cmdshell (MSSQL) or INTO OUTFILE (MySQL)
- Data exfiltration of all user records

### Reproduction Steps
1. Send request: `GET /api/user?id=1' OR '1'='1`
2. Observe all user records returned
3. Confirm via time-based: `GET /api/user?id=1' AND SLEEP(5)--`

### Request
```
GET /api/user?id=1' UNION SELECT 1,@@version,3,database()--
Host: target.com
```

### Response
```json
{
  "id": 1,
  "name": "Microsoft SQL Server 2019",
  "role": "admin",
  "db": "target_prod"
}
```

### Remediation
- Use parameterized queries (prepared statements)
- Validate and sanitize all user input
- Apply principle of least privilege to database accounts

### References
- OWASP: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
```
