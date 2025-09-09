---
title: Service Name
tags: [service, enum]          # add more: windows, linux, fileshare, database, remote, mail, monitoring, legacy, etc.
service: Service Name
protocol: ['tcp']              # e.g., ['udp'], or ['udp','tcp']
port: [0000]                   # list all common ports
auth: ['password']             # e.g., ['anonymous','password','ntlm','kerberos','certificate','default-creds']
tools: ['nmap']                # primary tools you actually use
notes: "One-line reminder of gotchas/high-value checks"
---

## Common Attack Paths

### Enumeration
- [ ] Primary nmap probe → `nmap -p<ports> --script=<service>* <target>`
- [ ] Quick/banner check → `nc <target> <port>`
- [ ] Tool-based enum → `<tool> <args>`
- [ ] Version/fingerprint → `<command>`

### Attack Paths
- Pattern 1 → what it enables
- Pattern 2 → what it enables
- Pattern 3 → what it enables
- Exploit family (if applicable)

### Auxiliary Notes
- Practical gotcha 1 (OPSEC / AV / logging)
- Practical gotcha 2 (permissions, mount flags, protocol quirks)
- Post-ex ideas (loot locations, easy persistence)