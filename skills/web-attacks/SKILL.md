---
name: web-attacks
description: Web application attack techniques — SQL injection, XSS, SSRF, SSTI, XXE, command injection, file upload, path traversal, deserialization, JWT/OAuth/SAML, prototype pollution, HTTP smuggling, GraphQL, race conditions, logic flaws, info disclosure, client-side, NoSQL injection. Use when the target is an HTTP application, API, browser client, auth flow, or template engine.
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, curl, and internet access.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch
metadata:
  user-invocable: "true"
  argument-hint: "<vulnerability-type or URL>"
---

# Web Attacks

Routing skill for web vulnerability techniques. Match the entry signal to the correct document.

## Signal → Document Map

| Signal | Document |
|--------|----------|
| SQL error, login form, numeric ID, search, ORDER BY | [SQL Injection](../../01-web-attacks/sql-injection/index.md) |
| MongoDB `$gt/$ne`, `$where`, `$regex` | [NoSQL Injection](../../01-web-attacks/nosql-injection/index.md) |
| User input reflected in HTML/JS/DOM | [XSS](../../01-web-attacks/xss/index.md) |
| URL input, webhook, image fetch, PDF export | [SSRF](../../01-web-attacks/ssrf/index.md) |
| Template engine (Jinja2/Twig/Mako/EJS), `{{ }}` in output | [SSTI](../../01-web-attacks/ssti/index.md) |
| XML input, SOAP, SVG upload, DOCX upload | [XXE](../../01-web-attacks/xxe/index.md) |
| Shell metachar in params, `;`, `\|`, `` ` ``, `$()` | [Command Injection](../../01-web-attacks/command-injection/index.md) |
| File upload form, image processing, avatar | [File Upload](../../01-web-attacks/file-upload/index.md) |
| Path parameter, `file=`, `template=`, `page=` | [Path Traversal](../../01-web-attacks/path-traversal/index.md) |
| Serialized object, pickle, Java ObjectInputStream | [Deserialization](../../01-web-attacks/deserialization/index.md) |
| JWT token in Authorization header | [JWT Attacks](../../01-web-attacks/auth-jwt/index.md) |
| OAuth flow, SAML assertion, redirect_uri | [OAuth/SAML](../../01-web-attacks/auth-oauth-saml/index.md) |
| Node.js app, merge/clone/deep-extend | [Prototype Pollution](../../01-web-attacks/prototype-pollution/index.md) |
| Reverse proxy, Content-Length / Transfer-Encoding | [HTTP Smuggling](../../01-web-attacks/http-smuggling/index.md) |
| GraphQL endpoint, introspection query | [GraphQL](../../01-web-attacks/graphql/index.md) |
| Concurrent requests to state-changing endpoint | [Race Conditions](../../01-web-attacks/race-conditions/index.md) |
| Payment flow, password reset, coupon/voucher | [Logic Flaws](../../01-web-attacks/logic-flaws/index.md) |
| Stack trace, .git/.env, CORS *, verbose errors | [Info Disclosure](../../01-web-attacks/info-disclosure/index.md) |
| DOM postMessage, browser features, CSP gaps | [Client-Side](../../01-web-attacks/client-side/index.md) |

## Quick Recon

```bash
# Always start here
curl -sI http://target/
curl -sv http://target/ 2>&1 | head -50
# Check common leak paths
for p in robots.txt .git/HEAD .env .DS_Store /.well-known/ /admin /debug /api /swagger; do
  curl -sk -o /dev/null -w "$p %{http_code}\n" "http://target/$p"
done
```

## When Blocked

→ Load [Bypass Toolkit](../../00-methodology/04-bypass-toolkit.md)
→ Load [WAF Bypass Payloads](../../payloads/waf-bypass.md)
