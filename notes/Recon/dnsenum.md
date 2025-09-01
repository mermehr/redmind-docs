---
title: DNSEnum
tags: [tool, dns, recon, enum, cheatsheet, vhost]
service: DNS
protocol: ['udp', 'tcp']
tools: ['dnsenum']
notes: "DNS record enumeration, subdomain brute force, zone transfer, WHOIS, Google scraping"
---

# DNSEnum Cheat Sheet

## Basic Usage
`dnsenum <domain>`

---

## Common Options

- `--enum` → shortcut to enable several enumeration features  
- `-f <wordlist>` → brute-force subdomains with wordlist  
- `-r` → recursive brute-force (enumerate sub-subdomains)  
- `-p <num>` → set number of threads  
- `--dnsserver <ip>` → specify DNS server to use  
- `-o <file>` → output results to file  

---

## Practical Examples

- Basic enumeration:  
  `dnsenum --enum inlanefreight.com`

- Subdomain brute force with SecLists:  
  `dnsenum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`

- Recursive subdomain enumeration:  
  `dnsenum inlanefreight.com -r`

- Specify DNS server:  
  `dnsenum inlanefreight.com --dnsserver 8.8.8.8`

- Output to file:  
  `dnsenum inlanefreight.com -o results.txt`

---

## Features Recap

- DNS Record Enumeration (A, AAAA, NS, MX, TXT)  
- Zone Transfer attempts on discovered NS  
- Subdomain brute-forcing with wordlists  
- Google scraping for additional subdomains  
- Reverse lookups (IP → domains)  
- WHOIS lookups for domain ownership  

---

## Notes
- Zone transfers (`AXFR`) often blocked but high-value when successful.  
- Recursive enumeration expands attack surface.  
- Use with SecLists for comprehensive brute-force results.  