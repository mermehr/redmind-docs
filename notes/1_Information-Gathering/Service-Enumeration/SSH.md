---
title: "Secure Shell"
date: 2025-08-23
tags: [ipmi, service]
port: [tcp, 22]

---

# Secure Shell

## Enumeration

*Common Commands:*

*SSH-Audit:*
 ```bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py 10.129.14.132
```
*Change Authentication Method - brute force:*

```bash
ssh -v cry0l1t3@10.129.14.132
ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
```