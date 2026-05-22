# DNS and Web OSINT

## Trigger
Load when performing DNS reconnaissance (TXT, MX, CNAME, zone transfers), mining WHOIS history, analyzing SSL certificate chains, using Google dorking for hidden documents, querying the Wayback Machine for historical content, investigating Tor relays, analyzing GitHub repositories for leaked credentials, or identifying fake service banners.

## Attack Surface
Target characteristics: domain names with public DNS records, SSL/TLS certificates exposing server infrastructure, archived web pages with deleted content, WHOIS registration data (historical and current), Google Docs/Sheets with loose sharing permissions, GitHub repos with commit history containing credentials, Tor hidden services, and services running on unexpected ports with custom banners.

## Decision Tree
1. DNS recon: dig for TXT, MX, CNAME, AAAA, and NS records on the target domain and subdomains.
2. Try zone transfer (`dig axfr`) -- often misconfigured.
3. WHOIS lookup: check creation date, registrant email/org, name servers.
4. Historical WHOIS: use SecurityTrails, WhoisXML API, or DomainTools for pre-privacy data.
5. Wayback Machine: query CDX API for all archived URLs of the target.
6. SSL certificate: use Censys or `openssl s_client` for certificate chain analysis.
7. Google dorking: search for indexed documents, open directories, and password leaks.
8. GitHub: check commits, issues, PRs for credentials or hidden data.

## Techniques

### DNS Reconnaissance
```bash
# Basic record types
dig -t TXT target.ctf.domain.com
dig -t MX target.ctf.domain.com
dig -t CNAME target.ctf.domain.com
dig -t A target.ctf.domain.com
dig -t ANY target.ctf.domain.com

# Zone transfer (critical -- often misconfigured)
dig axfr @ns1.target.domain.com target.domain.com

# DNSSEC zone walking (NSEC records)
dig -t NSEC target.domain.com

# Check for DMARC/TXT records
dig TXT _dmarc.target.domain.com

# Subdomain brute-force
for sub in $(cat subdomains.txt); do
    host "$sub.target.domain.com" 2>/dev/null | grep "has address"
done
```

### WHOIS Investigation
```bash
# Basic WHOIS
whois target.com

# Key fields: Registrant name/email, Creation date, Name servers, Registrar

# IP WHOIS (find network owner)
whois 1.2.3.4
# Look for: NetName, OrgName, CIDR range, abuse contact

# ASN lookup
whois -h whois.radb.net AS12345
# Or: curl https://bgp.tools/as/12345
```

### Historical WHOIS
```bash
# SecurityTrails API
curl "https://api.securitytrails.com/v1/domain/target.com/whois" \
  -H "APIKEY: YOUR_KEY"

# Reverse WHOIS (find all domains by same registrant)
curl "https://reverse-whois-api.whoisxmlapi.com/api/v2" \
  -d '{"searchType":"current","mode":"purchase",
       "basicSearchTerms":{"include":["target@email.com"]}}'
```

### SSL Certificate Chain Analysis
```bash
# Fetch and display certificate chain
openssl s_client -connect target.com:443 -showcerts </dev/null 2>/dev/null

# Extract certificate details
echo | openssl s_client -connect target.com:443 2>/dev/null | \
    openssl x509 -text -noout

# Key fields: Subject, Issuer, Validity, SubjectAltName (SAN)
# SANs reveal additional domains/subdomains on the same server

# Shodan search by SSL fingerprint
shodan search 'ssl.cert.fingerprint:"SHA256_HASH"'
```

### Wayback Machine
```bash
# Find all archived URLs for a domain
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=timestamp,original,statuscode"

# Download a specific archived page
curl "http://web.archive.org/web/20230101000000/target.com/page"

# Find historical profile images
curl "http://web.archive.org/cdx/search/cdx?url=pbs.twimg.com/profile_images/*&output=json"
```

### Google Dorking
```text
site:target.com filetype:pdf
site:target.com intitle:"index of"
site:target.com inurl:admin
site:target.com "confidential" filetype:doc
site:linkedin.com "company name" intern

# Image search faces filter (strips logos/banners):
# Append &tbs=itp:face to Google Image search URL

# Other TBS parameters:
itp:face        Faces only
itp:clipart     Logos, icons
itp:animated    Animated images
ic:specific,isc:green   Dominant color
isz:l           Large images
isz:lt,islt:2mp More than 2 megapixels
```

### Google Docs/Sheets Enumeration
```bash
# Try these URL patterns on discovered Google Docs IDs:
# /export?format=csv           Export as CSV
# /pub                         Published version
# /gviz/tq?tqx=out:csv         Visualization API CSV
# /htmlview                    HTML view

# Sheet IDs are stable even when sharing settings change
```

### Shodan SSH Fingerprint De-Anonymization
```python
# Find the real IP behind a Tor hidden service or CDN
import shodan

# Step 1: Get SSH fingerprint from target
# ssh-keyscan -t rsa target.onion | ssh-keygen -lf - -E md5

# Step 2: Search Shodan for matching fingerprint
api = shodan.Shodan('YOUR_API_KEY')
results = api.search('ssh.fingerprint:"ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90"')
for result in results['matches']:
    print(f"IP: {result['ip_str']}, Port: {result['port']}")

# Also works with TLS certificate fingerprints
# shodan search 'ssl.cert.fingerprint:"SHA256_HASH"'
```

### Fake Service Banner Detection
```bash
# Never trust port numbers alone -- always fingerprint the service

# SYN scan finds port open
nmap -sS target.ctf

# Version detection reveals the deception
nmap -sV -sC target.ctf -p 22
# The flag may be in the banner itself

# Or connect directly with netcat
nc target.ctf 22
# Banner may contain: MetaCTF{flag}

# For TLS-wrapped services
openssl s_client -connect target.ctf:443
```

### GitHub Repository Mining
```bash
# Clone repo and extract every author/committer email
git clone https://github.com/TARGET_USER/REPO.git
cd REPO
git shortlog -sne
# Output: commits  Name <email> -- the email is often the valid login

# Get all author emails at once
git log --format="%an <%ae>%n%cn <%ce>" | sort -u

# GitHub API: list public events (contains commit data)
gh api "users/TARGET_USER/events/public" --paginate | \
    jq -r '.[] | .payload.commits[]?.author.email' | sort -u

# Check .mailmap, CONTRIBUTORS file, and GPG signatures
git log --show-signature
```

### .DS_Store Directory Enumeration
```bash
# Download and parse .DS_Store files for hidden filenames
curl -sO "http://target/uploads/.DS_Store"
python3 -m dsstore .DS_Store
# Exposes filenames the Finder ever saw, even if not accessible via directory listing
```

### Telegram Bot Investigation
```python
import requests
import sqlite3

# Step 1: Find bot references in browser history
conn = sqlite3.connect("History")  # Chrome/Edge history DB
cur = conn.cursor()
cur.execute("SELECT url FROM urls WHERE url LIKE '%t.me/%'")
# Example: https://t.me/comrade404_bot

# Step 2: Interact with bot
# Start with /start or custom command
# Bot may ask verification questions from forensic analysis

# Common verification question sources:
# - "Which user account used for X?" -> Browser history
# - "Which account was modified?" -> Security.evtx Event 4781
# - "What file was accessed?" -> MRU, Recent files, Shellbags
```

### Tor Relay Lookups
```text
# Check Tor relay by fingerprint
https://metrics.torproject.org/rs.html#simple/<FINGERPRINT>

# Check family members and sort by "first seen" date
# Family members may reveal operator identity
```

### Cross-Challenge Container IP Reuse
In Docker-hosted CTFs, all challenges in the same subnet share internal IPs. Leak `REMOTE_ADDR` from one challenge (via SSRF/command injection) and apply it to gated challenges requiring specific `X-Forwarded-For` or MD5(IP)-based paths.

## Bypass
- If zone transfer is blocked (`dig axfr` returns no results), try IXFR (`dig domain IXFR=0`) or NSEC walking for DNSSEC zones.
- If WHOIS data is privacy-redacted, use historical WHOIS (SecurityTrails, DomainTools) to find pre-privacy records.
- If a domain is behind Cloudflare, use Shodan/Censys to find the origin IP: search for the SSL certificate fingerprint or SSH host key.
- If Google dorking returns too many results, narrow with `-inurl:spamword` and date range filters.
- If GitHub commits are force-pushed and "lost", they still appear in pull request comments and issue references.

## Verification
- DNS TXT record returns the expected flag string for the target domain/subdomain.
- WHOIS record matches expected dates, registrant, or name servers from challenge context.
- Wayback Machine returns archived snapshots with status code 200 for the target URL at relevant dates.
- SSL certificate SANs reveal additional subdomains that resolve and serve content.
- Shodan SSH fingerprint search returns the real IP matching the Tor hidden service.
- Netcat banner on the port returns the flag without further exploitation.

## Pitfalls
- DNS changes may take time to propagate; query multiple resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8).
- WHOIS privacy protection (GDPR/ICANN) now redacts most registrant data by default -- historical records are essential.
- The Wayback Machine may not have snapshots for every date; try different years and months.
- SSL certificates expire -- a currently invalid cert may be the historically correct one.
- Shodan free tier has limited query credits; batch searches carefully.
- GitHub API has rate limits (60/hr unauthenticated, 5000/hr authenticated).
- Google dorking with `site:` may miss subdomains -- verify with a separate `site:*.target.com` query.
