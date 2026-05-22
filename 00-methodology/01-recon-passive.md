# Passive Reconnaissance

## Trigger
Load at the start of Phase 2: Recon. Target is defined but no active probing has occurred.

## Attack Surface
Target domains, IP ranges, organization names. All information exists in third-party databases — no direct target contact needed.

## Decision Tree

```
Target scope received
  |
  ├── Domain(s) in scope?
  |     ├── crt.sh → subdomains, historical certs
  |     ├── SecurityTrails → DNS history, associated domains
  |     ├── Wayback Machine → historical URLs, JS files
  |     └── Censys → certificate chain, services
  |
  ├── IP ranges in scope?
  |     ├── bgp.he.net → ASN → IP blocks → adjacent ranges
  |     ├── Shodan/FOFA → exposed services, banners
  |     └── Reverse DNS → domain-to-IP mapping
  |
  ├── Organization name?
  |     ├── GitHub → org repos, leaked secrets (api_key, .env, password)
  |     ├── LinkedIn → employee names, tech stack mentions
  |     └── Google dorks → exposed configs, directory listings
  |
  └── Compile: deduplicated asset inventory
```

## Techniques

### Certificate Transparency
Query crt.sh for all certificates issued to the target domain and its subdomains. Certificates often expose internal hostnames, staging servers, and pre-production environments not linked from the main site.

### Historical Snapshots
The Wayback Machine captures HTML, JS, and API responses across time. Extract:
- Old endpoints that may still exist
- JS files containing API routes
- Comments with internal paths
- Previous versions of login/admin panels

### Code Repository Search
Search public code hosts for:
- `org:target password`, `org:target secret`, `org:target api_key`
- `.env` files committed by employees
- Configuration files with internal hostnames
- CI/CD configs revealing infrastructure

### DNS Enumeration
- Subdomain enumeration via SecurityTrails, AlienVault OTX
- Zone transfer attempt (rare but high-value)
- SPF/DMARC records revealing mail infrastructure
- TXT records with verification tokens

### Technology Fingerprint
- Favicon hash → search engines → identify CMS/framework
- HTTP headers → server, framework versions
- Error pages → stack traces, internal paths

## Output Format

| Asset | Type | Source | Confidence |
|-------|------|--------|------------|
| api.target.com | subdomain | crt.sh | high |
| /admin/backup.zip | endpoint | Wayback | medium |
| AWS key in repo | credential | GitHub | high |

## Pitfalls
- Over-collecting: 10,000 subdomains with 9,900 dead is noise, not signal
- Trusting one source: cross-validate across 3+ sources before acting
- Skipping the dedup step: duplicates waste time in active enumeration
- Passive recon that's actually active: port scanning during recon phase
