# Security Testing Tools Reference

A comprehensive index of security testing tools organized by capability domain. Includes reconnaissance, exploitation, post-exploitation, and specialized tools.

---

## Reconnaissance & Information Gathering

### Network Scanning

| Tool | Purpose | Platform | Command Example |
|------|---------|----------|-----------------|
| Nmap | Port scanning, OS detection, service version | Linux/Win | `nmap -sV -sC target` |
| Masscan | High-speed port scanning | Linux | `masscan -p1-65535 target --rate=10000` |
| Zmap | Internet-wide scanning | Linux | `zmap -p 443 target_range` |
| RustScan | Fast scanner with Nmap integration | Linux | `rustscan -a target -- -sV` |
| Unicornscan | Async scan, TCP/IP stack fingerprint | Linux | `unicornscan target` |
| Naabu | Fast port scanner (ProjectDiscovery) | Linux | `naabu -host target` |

### Web Discovery

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| FFUF | Web fuzzing | `ffuf -u http://target/FUZZ -w wordlist.txt` |
| Gobuster | Directory/Subdomain brute force | `gobuster dir -u http://target -w wordlist.txt` |
| Dirb | Directory brute force | `dirb http://target wordlist.txt` |
| Dirsearch | Directory scanning | `dirsearch -u http://target` |
| httpx | HTTP probing (ProjectDiscovery) | `httpx -l targets.txt -status-code -title` |
| subfinder | Subdomain discovery | `subfinder -d target.com` |
| Amass | Subdomain enumeration | `amass enum -d target.com` |
| httprobe | Probe live hosts from list | `cat domains.txt | httprobe` |
| Aquatone | Screenshot + visual inspection | `aquatone -sites targets.txt` |
| Eyewitness | Web screenshot tool | `eyewitness -f urls.txt` |

### DNS

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Dig | DNS lookup | `dig any target.com` |
| Nslookup | DNS query | `nslookup target.com` |
| Host | DNS lookup utility | `host -l target.com ns1.target.com` |
| Dnsrecon | DNS enumeration | `dnsrecon -d target.com` |
| Dnsenum | DNS enumeration | `dnsenum target.com` |
| Fierce | DNS brute force | `fierce -domain target.com` |

### Certificate Transparency

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| crt.sh | Certificate search | `curl -s "https://crt.sh/?q=%25.target.com&output=json"` |
| CertSpotter | Monitor cert issuance | `certspotter -domain target.com` |

### WHOIS / ASN

| Tool | Purpose |
|------|---------|
| whois | Domain/IP ownership lookup |
| ASNLookup | ASN enumeration |
| BGP.he.net | BGP routing information |

---

## Web Application Testing

### Interception Proxies

| Tool | Purpose | Notes |
|------|---------|-------|
| Burp Suite Pro | Full-featured web proxy | Industry standard, paid |
| OWASP ZAP | Open-source proxy | Free alternative |
| mitmproxy | CLI intercepting proxy | Python-based, scriptable |
| Fiddler | Windows proxy | .NET focused |

### SQL Injection

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| SQLMap | Automated SQL injection | `sqlmap -u "http://target/page?id=1"` |
| jSQL Injection | GUI SQLi tool | `java -jar jsql-injection.jar` |
| NoSQLMap | NoSQL injection | `nosqlmap.py -u "http://target"` |
| sqliv | SQLi vulnerability scanner | `sqliv -u "http://target"` |

### XSS

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| XSStrike | XSS detection | `python xsstrike.py -u "http://target?q=test"` |
| Dalfox | XSS scanner | `dalfox url http://target?q=test` |
| BeEF | Browser exploitation | `beef-xss` |
| XSS Hunter | Blind XSS detection | Self-hosted, `https://xsshunter.com` |

### SSRF

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| SSRFmap | SSRF exploitation | `python ssrfmap.py -r request.txt -p param` |
| Gopherus | Gopher SSRF payload | `python gopherus.py --exploit redis` |
| Interactsh | OOB interaction (ProjectDiscovery) | `interactsh-client` |

### File Inclusion

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| LFISuite | LFI exploitation | `python lfisuite.py` |
| PHP filter chain gen | php://filter RCE | `python php_filter_chain_generator.py` |
| FMF (File Monitor Fuzz) | File path fuzzing | `fmf -u http://target/FUZZ.php` |

### JWT

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| jwt_tool | JWT testing | `python jwt_tool.py <token>` |
| jwtenizer | JWT exploitation | `python jwtenizer.py` |
| jwt-cracker | Key brute force | `jwt-cracker <token> <wordlist>` |
| flask-unsign | Flask session decode/forge | `flask-unsign --unsign --cookie <cookie>` |
| JWT Editor (Burp) | JWT manipulation | Burp Extension |

### GraphQL

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| GraphiQL | GraphQL introspection | Web interface |
| InQL | GraphQL scanner (Burp) | Burp extension |
| graphql-map | Schema mapping | `python graphql_map.py -u http://target/graphql` |
| Clairvoyance | GraphQL introspection bypass | `clairvoyance -u http://target/graphql` |

### SSRF / XXE Testing

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| OOBext | OOB data exfiltration | `python oobext.py` |
| XXER | XXE exploitation | `python xxe.py -r request.txt` |
| Interactsh | OOB interaction detection | `interactsh-client -v` |

---

## Binary Exploitation

| Tool | Purpose | Notes |
|------|---------|-------|
| pwntools | CTF exploit development | Python library |
| GEF (pwndbg) | GDB plugin | Enhanced debugging |
| ROPgadget | ROP gadget finder | `ROPgadget --binary binary` |
| Ropper | ROP gadget tool | `ropper --file binary` |
| one_gadget | One-gadget RCE finder | `one_gadget libc.so.6` |
| angr | Symbolic execution | Python library |
| QEMU | Emulation for cross-arch | `qemu-arm ./binary` |
| Ghidra | Reverse engineering | SRE suite |
| IDA Pro | Disassembler | Commercial |
| Radare2 | Reverse engineering | Open-source |
| objdump | Binary analysis | Built-in Linux |
| checksec | Binary security check | `checksec --file=binary` |
| patchelf | ELF patching | `patchelf --set-interpreter ...` |
| LIEF | Binary format library | Python/C++ library |

---

## Post-Exploitation

### Active Directory

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Impacket | AD protocol suite | `impacket-secretsdump domain/user:pass@target` |
| CrackMapExec | AD post-exploitation | `cme smb 192.168.1.0/24 -u user -p pass` |
| BloodHound | AD relationship mapper | `bloodhound-python -d domain -u user -p pass` |
| Mimikatz | Credential extraction | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"` |
| Rubeus | Kerberos interaction | `Rubeus.exe kerberoast` |
| Certipy | ADCS exploitation | `certipy find -u user@domain -p pass -dc-ip dc` |
| PowerView | AD enumeration (PowerShell) | `Get-NetUser`, `Get-NetComputer` |
| pypykatz | Python Mimikatz | `pypykatz lsa minidump.dmp` |

### Privilege Escalation

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| LinPEAS | Linux enumeration | `./linpeas.sh` |
| WinPEAS | Windows enumeration | `winpeas.exe` |
| linux-smart-enum | Linux enumeration | `./lse.sh` |
| BeRoot | PE detection | `beRoot.exe` |
| PrivescCheck | PowerShell PE | `. .\PrivescCheck.ps1; Invoke-PrivescCheck` |
| PowerUp | Windows privilege escalation | `Invoke-AllChecks` |

### Payload Generation

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| MSFVenom | Metasploit payload gen | `msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=port` |
| ysoserial | Java deserialization | `java -jar ysoserial.jar CommonsCollections1 'cmd'` |
| ysoserial.net | .NET deserialization | `ysoserial.exe -f BinaryFormatter -g ...` |
| phpggc | PHP gadget chains | `phpggc Laravel/RCE1 system id` |
| Cobalt Strike | Commercial C2 framework | GUI + team server |

### Tunneling

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Chisel | SOCKS tunnel | `chisel server -p 8080 --reverse` |
| Ligolo-ng | Layer 2 tunnel | `ligolo-ng-proxy -hack 0.0.0.0:11601` |
| Frp | Reverse proxy | `frps -c frps.ini` |
| NPS | NAT/proxy tunnel | `nps` |
| sshuttle | VPN over SSH | `sshuttle -r user@host subnet` |
| Stowaway | Multi-level proxy | Multi-hop tunnel |
| Venom | Agent proxy | Admin/Agent architecture |

### Lateral Movement

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| PsExec | Remote execution (SMB) | `psexec \\target -u user -p pass cmd` |
| WMIExec | Remote execution (WMI) | `wmiexec.py domain/user:pass@target` |
| WinRM | Remote execution (WinRM) | `evil-winrm -i target -u user -p pass` |
| SchTaskExec | Scheduled task execution | `atexec.py domain/user:pass@target "cmd"` |
| DCOMExec | DCOM lateral movement | `dcomexec.py domain/user:pass@target` |

---

## Cryptography Testing

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Hashcat | Password cracking | `hashcat -m 1000 hash.txt wordlist.txt` |
| John the Ripper | Password cracking | `john --wordlist=wordlist.txt hash.txt` |
| RsaCtfTool | RSA CTF solving | `python RsaCtfTool.py -n n -e e --uncipher c` |
| xortool | XOR analysis | `xortool ciphertext` |
| CyberChef | Data transformation | Web tool |
| openssl | Cryptographic operations | `openssl enc -aes-256-cbc -d -in file.enc` |

---

## Network & Protocol Tools

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| tcpdump | Packet capture | `tcpdump -i eth0 -w capture.pcap` |
| Wireshark | Packet analysis | GUI |
| Scapy | Packet crafting | Python library |
| BetterCAP | MITM framework | `bettercap -eval "net.sniff on"` |
| Ettercap | MITM / ARP spoofing | `ettercap -T -M arp /target// /gateway//` |
| Responder | LLMNR/NBT-NS poisoner | `responder -I eth0` |
| Inveigh | Windows LLMNR poisoner | PowerShell |
| hping3 | Packet crafting | `hping3 -S -p 80 --flood target` |
| socat | Bidirectional relay | `socat TCP-LISTEN:8080,fork TCP:target:80` |
| netcat | TCP/UDP Swiss Army knife | `nc -lvnp 4444` |
| ncat | Enhanced netcat | `ncat --ssl -lvnp 4444` |

---

## Forensics & Memory Analysis

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| Volatility 3 | Memory analysis | `vol -f mem.dump windows.pslist` |
| Rekall | Memory forensics | `rekall -f mem.dump pslist` |
| binwalk | Firmware analysis | `binwalk firmware.bin` |
| foremost | File carving | `foremost -i disk.dd` |
| strings | Extract strings | `strings file.bin` |
| exiftool | Metadata extraction | `exiftool file.jpg` |

---

## Steganography

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| steghide | Image steganography | `steghide extract -sf image.jpg` |
| zsteg | PNG/BMP steg detection | `zsteg image.png` |
| stegsolve | Steganography solver | GUI |
| jsteg | JPEG steganography | `jsteg extract image.jpg` |

---

## Mobile Application

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| APKTool | APK decompilation | `apktool d app.apk` |
| jadx | Java decompiler | `jadx app.apk` |
| Frida | Dynamic instrumentation | `frida -U -l script.js com.example.app` |
| Objection | Mobile exploration | `objection --gadget com.example.app explore` |
| Mobile Security Framework | Automated mobile analysis | `python3 mvs.py` |
| FRIDA-DEXDump | DEX extraction | `frida-dexdump -U` |
| Android Studio | Emulator + debugging | Official Android IDE |

---

## AI / LLM Security

| Tool | Purpose | Notes |
|------|---------|-------|
| Garak | LLM vulnerability scanner | Automated probing |
| PromptInject | Prompt injection testing | Pattern-based |
| TextFooler | Adversarial text | Perturbation attacks |
| Counterfit | AI security testing | Microsoft tool |
| ART (Adversarial Robustness Toolbox) | ML attack library | IBM tool |

---

## Collaboration & Reporting

| Tool | Purpose |
|------|---------|
| Metasploit | Exploit framework |
| Faraday | Collaborative pentest platform |
| Dradis | Reporting framework |
| CherryTree | Note taking |
| Joplin | Note taking (markdown) |

---

## Wordlists

| Wordlist | Source | Purpose |
|----------|--------|---------|
| SecLists | GitHub (danielmiessler) | General purpose |
| RockYou | Leak | Password cracking |
| fuzzdb | GitHub | Web fuzzing |
| Chinese-passwords | Various | Chinese target password lists |
| DefaultCreds-Cheat-Sheet | GitHub | Default credential list |
| PayloadsAllTheThings | GitHub | Payload collection |
| One-Liners | GitHub (viperbluff) | One-liner payloads |

---

## Framework-Specific Exploit Tools

| Framework | Tool | Purpose |
|-----------|------|---------|
| Struts2 | struts2-scanner | Scan for Struts2 RCE |
| Shiro | ShiroScan / Shiro_exploit | Shiro rememberMe exploitation |
| WebLogic | weblogic_scanner, WebLogicExploit | WebLogic CVE exploitation |
| ThinkPHP | thinkphp_gui, thinkphp_scanner | ThinkPHP RCE |
| Fastjson | fastjson_tool, JNDIExploit | Fastjson RCE |
| Spring | SpringBoot-Scan | Actuator + RCE testing |
| Log4j | log4j-scan, Log4jSherlock | Log4Shell detection |
| Exchange | proxylogon, proxyshell, exechange | Exchange RCE |
| Jenkins | jenkins-scanner | Jenkins exploitation |
