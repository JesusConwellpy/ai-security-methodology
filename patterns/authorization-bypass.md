# Authorization Bypass Patterns

Common authorization bypass vulnerability patterns derived from real-world bug bounty reports. Covers IDOR, privilege escalation, and access control failures.

---

## Root Cause Categories

### 1. Email/Identity Verification Bypass

**Root Cause:** The application allows committing identity changes (email, phone) or performing privileged actions without verifying the new identity. Typically caused by skipping server-side verification or accepting unverified claims.

**Detection Strategy:**
1. Initiate an email change to an attacker-controlled address
2. Intercept the verification step and either skip it (navigate to next step directly) or force-complete it
3. If the email is updated without proper verification, attempt password reset on the victim's account
4. Also test phone number changes, security question changes, and 2FA device changes

### 2. Unauthenticated Access to Admin/Internal APIs

**Root Cause:** Internal APIs or admin endpoints assume all traffic is from authenticated sources due to network segmentation. When these are exposed to the internet without authentication, anyone can access them.

**Detection Strategy:**
1. Map all API endpoints via documentation (Swagger), JS files, or directory fuzzing
2. Test each endpoint without authentication headers
3. Focus on naming conventions that suggest internal use: `/internal/`, `/admin/`, `/api/v1/`, `/private/`
4. Check for GraphQL introspection endpoints without auth
5. Look for internal-only status/health/metrics endpoints

### 3. Subscription/Plan Manipulation via Response Modification

**Root Cause:** The application sends subscription plan status to the client (e.g., `{"plan": "free", "trial": true}`) and trusts the client's response to authorize features. Intercepting and modifying the response gives premium access.

**Detection Strategy:**
1. Create a free/basic account
2. Monitor the API responses that return subscription information after login
3. Intercept and modify plan-related fields: `"plan": "premium"`, `"trial": false`, `"expired": false`
4. Access premium features and confirm they are now unrestricted
5. Test both response modification and request-level feature gating

### 4. IDOR via Predictable or Enumerable Identifiers

**Root Cause:** Object references (user IDs, order numbers, document IDs) are predictable (sequential integers, timestamps, hashed values) and no authorization check verifies ownership.

**Detection Strategy:**
1. Identify endpoints that accept object identifiers: `/api/user/{id}`, `/api/order/{order_id}`
2. Create a resource with one account, then attempt to access it with another
3. Test incremental/sequential identifiers
4. Look for IDOR in lists: `/api/users` where one user can list all users
5. Test IDOR in nested operations: `/api/order/{id}/refund` where order belongs to another user

---

## Common Attack Vectors

### Email Verification Bypass

```http
-- Step-skip during email change
POST /api/account/change-email HTTP/1.1
{"new_email": "attacker@example.com"}

-- Skip verification step by directly calling confirm
POST /api/account/confirm-email HTTP/1.1
{"token": "any_token_value"}

-- Response manipulation
-- Original response after verification step:
{"verified": false, "email": "victim@example.com"}
-- Modified response:
{"verified": true, "email": "attacker@example.com"}
```

### API Authorization Bypass

```http
-- Accessing internal API without auth
GET /api/v1/internal/users HTTP/1.1
# Should get 401, but may return data

-- Manipulating authorization header
GET /api/v1/admin/users HTTP/1.1
Authorization: null

-- GraphQL introspection without auth
POST /api/graphql HTTP/1.1
Content-Type: application/json

{"query": "{__schema{types{name fields{name}}}}"}

-- Trying alternative auth methods
GET /api/v1/users HTTP/1.1
Authorization: Bearer guest
Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=
X-API-Key: test
```

### Subscription/Premium Bypass

```http
-- Intercept post-login subscription response
HTTP/1.1 200 OK
Original:
{"subscription": "free", "features": ["basic"]}
Modified:
{"subscription": "premium", "features": ["basic", "premium", "admin"]}

-- Feature-gate manipulation in request
POST /api/content/create HTTP/1.1
{"content": "test", "features": ["premium"]}

-- Trial expiration manipulation
POST /api/account/reactivate HTTP/1.1
{"plan": "enterprise", "coupon": "INTERNAL50"}
```

### IDOR Detection

```http
-- Sequential ID testing
GET /api/user/1001/profile
GET /api/user/1002/profile  # Different user
GET /api/user/1003/profile  # Different user

-- UUID/hash IDOR (check if UUIDs are predictable or exposed elsewhere)
GET /api/document/a1b2c3d4/details
# If this UUID was leaked in a previous response, try:
GET /api/document/a1b2c3d5/details
GET /api/document/a1b2c3d6/details

-- Mass assignment via IDOR
PUT /api/user/1002/profile
{"email": "attacker@example.com", "role": "admin"}

-- Nested resource IDOR
GET /api/order/5001/invoice
GET /api/order/5001/refund
DELETE /api/document/2001
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Bounty |
|--------|---------------|-----------|--------|
| Insightly | Email verification bypass | Skip verif step, update email without confirmation | Bounty |
| Azure API | Unauthenticated access to internal API | Internal API exposed without auth on public internet | Bounty |
| NordVPN | Subscription bypass via response manipulation | Modify `{"plan": "free"}` to `{"plan": "premium"}` in response | Bounty |
| U.S. DoD | Authorization bypass in admin panel | Direct access to admin functions via path discovery | N/A |
| CSRF -> ATO (2699029) | CSRF to account takeover | Profile edit CSRF with no token | N/A |
| CSRF -> ATO (2712857) | CSRF to account takeover | No CSRF protection on profile edit | N/A |
