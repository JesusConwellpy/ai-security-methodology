---
name: osint
description: Open Source Intelligence techniques — social media investigation, geolocation from images, DNS/web reconnaissance. Use when gathering intelligence from publicly available sources, identifying a person/location/organization, or performing passive reconnaissance.
license: MIT
compatibility: Requires filesystem-based agent with bash, Python 3, curl, and internet access.
allowed-tools: Bash Read Write Edit Glob Grep WebSearch WebFetch
metadata:
  user-invocable: "true"
  argument-hint: "<target or image-path>"
---

# OSINT

## Document Map

| Target | Document |
|--------|----------|
| Social media accounts, usernames, profile analysis, Unicode steganography | [Social Media](../../09-osint/social-media.md) |
| Image location, EXIF, reverse image search, satellite analysis, maps | [Geolocation](../../09-osint/geolocation.md) |
| DNS records, WHOIS, SSL certificates, Wayback Machine, Google dorks, Shodan | [DNS & Web Recon](../../09-osint/dns-web.md) |

## Image Geolocation Checklist

```bash
# EXIF data
exiftool image.jpg | grep -iE '(GPS|Location|Date|Camera|Make)'

# Reverse image search (describe approach, do not automate)
# - Google Lens: upload or search by URL
# - Yandex: better for CIS/Asia
# - TinEye: oldest index
# - Baidu: China-specific images

# What to look for in the image:
# - Road signs, license plates, business names, phone numbers
# - Architecture style, vegetation, climate indicators
# - Street markings, driving side, power outlets
# - Language on signs, advertisements, product labels
```

## DNS Recon

```bash
# All records
dig ANY target.com
# Zone transfer (rare)
dig AXFR target.com @ns1.target.com
# Specific records
dig A target.com && dig AAAA target.com
dig MX target.com && dig TXT target.com
dig CNAME www.target.com
# Subdomain enumeration
for sub in $(cat subdomains.txt); do
    host "$sub.target.com" 2>/dev/null | grep -E "has (IPv6 )?address"
done
```

## Google Dorks

```
site:target.com filetype:pdf confidential
site:target.com intitle:"index of"
site:target.com inurl:admin
site:target.com ext:sql | ext:bak | ext:old
site:github.com "target.com" password OR secret OR api_key
```
