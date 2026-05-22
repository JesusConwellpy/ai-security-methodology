# Active Enumeration

## Trigger
Load when Phase 3: Enum begins. Passive recon has produced an asset inventory. Time to probe and fingerprint.

## Attack Surface
Live domains, subdomains, IP addresses identified during passive recon.

## Decision Tree

```
Asset inventory (from Phase 2)
  |
  For each domain/IP:
  |
  ├── Port scan (top 1000 TCP + top 100 UDP)
  |     └── Open ports → services map
  |
  ├── For each open port:
  |     ├── Banner grab → service + version
  |     ├── Default credential check
  |     └── Known vulnerability match (version lookup)
  |
  ├── For each HTTP service:
  |     ├── Directory enumeration (common paths)
  |     ├── JS extraction → API routes, hidden endpoints
  |     ├── Parameter discovery (GET/POST params, headers)
  |     ├── Technology stack fingerprinting
  |     └── Virtual host discovery (Host header fuzzing)
  |
  └── Output: live asset matrix
```

## Techniques

### Port Scanning
- Start with top 1000 TCP ports for initial survey
- Follow up with targeted scans on interesting services
- UDP scanning is slow — focus on DNS (53), SNMP (161), NTP (123)
- Use service-specific probes, not just SYN scans

### HTTP Service Enumeration

**Directory brute-force:**
- Common paths: `/admin`, `/api`, `/backup`, `/.git`, `/.env`, `/debug`, `/swagger`
- Archive files: `.zip`, `.tar.gz`, `.bak`, `.old`
- CI/CD artifacts: `.gitlab-ci.yml`, `Jenkinsfile`, `Dockerfile`

**JS analysis:**
- Extract all strings matching URL patterns
- Find API endpoint definitions (`/api/v1/`, `baseURL`)
- Locate hidden parameters and debug flags

**Parameter discovery:**
- Test each endpoint with common params: `id`, `page`, `file`, `url`, `path`, `redirect`
- Fuzz with parameter names from wordlists
- Check for mass assignment: send extra JSON fields

### Service Fingerprinting

Match banners and responses against vulnerability databases:
- Web servers: Apache, Nginx, IIS version → CVE lookup
- Frameworks: Laravel, Django, Spring Boot → known misconfigurations
- CMS: WordPress, Drupal, Joomla → plugin vulnerabilities
- China-specific: Weaver OA, Seeyon, Tongda, Landray, Yonyou, Kingdee

When a China vendor system is identified, load the vendor fingerprint dictionary for targeted credential and exploitation data.

### Virtual Host Discovery
- Fuzz `Host` header with common subdomains
- Test IP-based vs hostname-based access — different content = virtual host routing

## Output Format

```
Asset Matrix:
  target.com (1.2.3.4)
    ├── :80   Apache/2.4.41 → Laravel 8.x → /api/v1/users, /admin
    ├── :443  nginx/1.18.0 → React SPA → /graphql (introspection enabled)
    └── :8080 Tomcat 9.0.41 → /manager (default creds: tomcat:tomcat)
```

## Pitfalls
- Scanning too aggressively and triggering IDS alerts
- Missing services on non-standard ports (MySQL on port 8443)
- Skipping JS analysis — endpoints hidden in JS are the best attack surface
- Trusting version banners — services can lie about versions
