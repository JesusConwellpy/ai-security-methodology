# Telecommunications & ISP Industry Security Testing

Specialized security testing methodology for telecommunications and internet service providers. Covers SP/CP platforms, management systems, and subscriber infrastructure.

---

## Industry Overview

### Source Data Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Weak credentials | 58.2% | Default/weak admin passwords |
| Authorization bypass | 62.3% | Missing access control on admin functions |
| Information disclosure | 47.1% | Subscriber data exposure |
| Command injection | 35.5% | In network management interfaces |
| SQL injection | 41.3% | In subscriber portals |
| Cross-site scripting | 33.7% | In self-service portals |

---

## Attack Surface Overview

### SP/CP (Service Provider / Content Provider) Platforms

```yaml
services:
  - "SMS gateway / SMS SP platform"
  - "MMS gateway"
  - "Value-added service (VAS) platforms"
  - "Content provider dashboards"
  - "Short code management"
  - "Bulk SMS services"
  - "Ring back tone (RBT) platforms"
  - "WAP gateway"
  - "IVR (Interactive Voice Response) systems"

common_exposure:
  - SP/CP admin portals exposed to internet (62%)
  - Default credentials unchanged for internal systems (45%)
  - Legacy interfaces with no auth (28%)
```

### IoT / M2M Card Management

```yaml
services:
  - "SIM card management platform"
  - "eSIM management / RSP (Remote SIM Provisioning)"
  - "M2M connectivity platform"
  - "Device management"
  - "IoT data platform"
  - "NB-IoT management"
  - "LTE-M management"
  - "APN configuration portals"
  - "Usage monitoring dashboards"

vulnerability_patterns:
  - "IDOR on SIM profiles (access other customers' SIMs)"
  - "Missing auth on API endpoints"
  - "SMS OTP interception via SS7 flaws"
  - "Subscription manipulation (change plans without auth)"
```

### Network Management Systems (NMS)

```yaml
vendors:
  Huawei:
    - "U2000 NMS"
    - "M2000 NMS"
    - "iManager"
    - "eSight"
  ZTE:
    - "NetNumen NMS"
    - "ZTE-NMS"
  FiberHome:
    - "OTNM2000"
    - "FiberHome NMS"

vulnerability_patterns:
  - "Default credentials unchanged (58% of incidents)"
  - "Command injection in diagnostic functions"
  - "SNMP community strings set to public/private"
  - "Unrestricted Telnet/SSH access"
  - "Unpatched vulnerabilities in web interfaces"
```

### Billing & Operations Support Systems (BSS/OSS)

```yaml
systems:
  - "Customer Relationship Management (CRM)"
  - "Billing system"
  - "Charging system (OCS / online charging)"
  - "Provisioning system"
  - "Order management"
  - "Service activation platform"
  - "Subscriber data management (SDM)"
  - "Policy control (PCRF)"

vulnerability_patterns:
  - "IDOR on subscriber records"
  - "SQL injection in search/filter functions"
  - "Mass assignment on account modifications"
  - "Privilege escalation: CSR -> Admin"
  - "Price manipulation in catalog management"
```

---

## Sector-Specific Vulnerability Patterns

### Weak Credentials Distribution

Telecom equipment and platforms are disproportionately affected by default credentials (58.2% of findings):

```yaml
most_affected:
  - "NMS web interfaces"          # 71% weak credentials
  - "SP/CP admin portals"         # 65% weak credentials
  - "IoT management platforms"    # 58% weak credentials
  - "Billing system interfaces"   # 42% weak credentials
  - "API gateways"                # 35% weak credentials
```

### Authorization Bypass (62.3%)

```yaml
patterns:
  horizontal:
    - "View other SP's SMS delivery reports"
    - "Access other IoT customer's device data"
    - "Read other subscriber's billing info"
    - "Modify other customer's service plans"
    
  vertical:
    - "Operator -> Supervisor -> Admin"
    - "View-only -> Edit -> Delete"
    - "Read billing -> Modify billing -> Refund"
    
  common_endpoints:
    - "/api/sp/sms/report"
    - "/api/sim/profile"
    - "/api/subscriber/detail"
    - "/api/billing/invoice"
    - "/api/network/device/config"
```

### SMS / SS7 Related Attacks

```yaml
ss7_attacks:
  - "SMS interception (via SS7 MAP attacks)"
  - "Location tracking (any MSISDN)"
  - "Call/SMS redirection"
  - "Subscriber data extraction (IMSI, location)"
  - "Fraud: Premium SMS interception"
```

---

## China Telecom-Specific References

### Known VoE Vulnerability Classes

These vulnerability types have been documented in China telecom sector engagements:

```yaml
voe_cases:
  - "VoE SMS Gateway: No rate limiting on OTP delivery"
  - "VoE CRM: IDOR on subscribed services of any phone number"
  - "VoE Billing: Amount tampering in top-up flows"
  - "VoE SP Platform: SQL injection in SMS content search"
  - "VoE Provisioning: Arbitrary service activation without billing"
  - "VoE NMS: Command injection via SNMP trap handling"
  - "VoE IoT Platform: Mass assignment on SIM profile modification"
```

### Common Telecom Endpoint Patterns

```http
-- SP/CP Platform
/sp/admin/login
/sp/api/send
/sp/api/report
/sp/api/mo

-- IoT Management
/iot/admin/login
/iot/api/sim/{iccid}
/iot/api/device/{imei}
/iot/api/usage/{msisdn}

-- NMS
/nms/login
/nms/device/{ip}/config
/nms/network/topology
/nms/alarm/list

-- Billing
/billing/admin/login
/billing/api/subscriber/{msisdn}
/billing/api/invoice/{id}
/billing/api/charge

-- Self-care Portal
/portal/login
/portal/api/bill
/portal/api/service
/portal/api/payment
```

---

## Testing Methodology

### Initial Reconnaissance

```bash
# Service discovery on telecom IP ranges
nmap -sT -p 80,443,8080,8443,9090 target_range
nmap -sU -p 161,162 target_range  # SNMP

# SP platform discovery
# Look for specific paths:
/sp/
/cp/
/sms/
/mms/
/vas/
/rbt/
/wap/

# NMS discovery
/nms/
/manager/
/network/
/eoms/
/otnm/

# Billing discovery
/billing/
/ocs/
/crm/
/charging/
/provisioning/
```

### Auth Testing for Telecom Platforms

```yaml
default_credential_testing:
  - "admin/admin"
  - "admin/123456"
  - "admin/admin123"
  - "admin/<vendorname>"
  - "telecom/telecom"
  - "operator/operator"
  - "nms/nms"
  - "sp/sp"
  - "crm/crm"
  - "system/system"
  - "root/root"
  - "admin/password"
  - "admin/admin@123"
```

### API Testing for Telecom Services

```http
-- SMS gateway testing
POST /api/send HTTP/1.1
{"to": "target_number", "from": "spoofed_number", "content": "SPAM"}

-- SP admin testing (IDOR on reports)
GET /api/report/12345
GET /api/report/12346
GET /api/report/12347

-- IoT SIM management (IDOR on ICCID)
GET /api/sim/89860012345678901234
PUT /api/sim/89860012345678901234
{"status": "deactivated", "data_plan": "unlimited"}

-- Billing subscriber info
GET /api/subscriber/8613900000000
GET /api/billing/invoice/INV2024-00001

-- Provisioning API abuse
POST /api/provision/service
{"msisdn": "8613900000000", "service": "unlimited_data", "price": 0}
```

### Telecom-Specific Command Injection

```bash
# SNMP injection
snmpset -v2c -c public target \
  .1.3.6.1.4.1.999.1.1.1.0 s "| id"

# NMS diagnostic command injection
POST /nms/diag HTTP/1.1
{"ip": "127.0.0.1; whoami"}

# Ping / traceroute injection
POST /nms/tools/ping HTTP/1.1
{"target": "127.0.0.1 && id"}

# Device config abuse
POST /nms/device/config HTTP/1.1
{"ip": "192.168.1.1", "cmd": "show running-config"}
```

---

## Infrastructure Weakness Distribution

```yaml
telco_infrastructure_vulnerabilities:
  percentage_affected: 58%
  
  categories:
    - "SNMP Community Strings (public/private)":
        percentage: 38%
        impact: "Full network device configuration read/write"
    - "Telnet Enabled":
        percentage: 31%
        impact: "Unencrypted management access"
    - "Default Web Credentials":
        percentage: 29%
        impact: "Admin access to management interfaces"
    - "Unpatched Known CVEs":
        percentage: 24%
        impact: "RCE via known exploits"
    - "Information Disclosure":
        percentage: 21%
        impact: "Network topology, configs, subscriber data"
    - "Open Management Ports (inner)":
        percentage: 19%
        impact: "Direct attack surface on critical systems"
```

## Recommended Tooling

```bash
# Network device discovery
nmap
snmp-check
onesixtyone

# Telecom-specific
ss7map              # SS7 infrastructure mapping
sigtran_scanner      # SIGTRAN service discovery

# General web testing applicable to telecom
Burp Suite
ffuf
gobuster
sqlmap

# Subscriber data handling tests
custom scripts for MSISDN/ICCID enumeration

# SIM/IMEI manipulation
pySim                # SIM card utilities
```
