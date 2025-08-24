---
title: "Remote Desktop Protocol"
date: 2025-08-23
tags: [rdp, cpan, xfreedpp, service]
port: [tcp, 3389]
---

# Remote Desktop Protocol

## Enumeration

*Common Commands:*

`nmap -sV -sC 10.129.201.248 -p3389 --script rdp*`

*Trace for security - Threat hunters can find the scripts:*

`nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n`

### RDP Security Check - Installation & Check

```bash
sudo cpan
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

*Initiate an RDP Session*

`$ xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248`