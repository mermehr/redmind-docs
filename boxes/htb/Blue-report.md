# HTB: Blue

## Engagement Overview
**Target:** HTB: Blue  
**Box IP:** 10.10.10.40  
**Local IP:** 10.10.14.10
**Date:** 2025-07-10

---

### Objectives
- Exploit SMBv1 vulnerability to gain remote shell access
- Capture both user and root flags

---

## Service Enumeration

```
Nmap 7.94SVN scan initiated...

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 7 Professional 7601 SP1

Host Details:
- Hostname: HARIS-PC
- OS: Windows 7 Professional SP1
- Workgroup: WORKGROUP
- Message signing: disabled (smb1), optional (smb2)
- Guest account access: allowed
```

Scripts & Host Discovery:
- OS Fingerprinting confirmed Windows 7
- SMBv1 enabled and vulnerable
- No clock skew issues that impact payloads

---

## Methodologies

### Initial Access – EternalBlue Exploit (MS17-010)

**Vulnerability:**  
CVE-2017-0144 – Microsoft SMBv1 Remote Code Execution

**Tools & Payloads Used:**
- Metasploit `windows/smb/ms17_010_eternalblue` (❌ failed)
- Manual conversion and execution of ExploitDB PoC `42031.py` (✅ success)

**Penetration Result:**  
- Direct shell access obtained via Python payload modification

---

## Privilege Escalation

Not applicable. Initial exploit yielded SYSTEM-level shell.

---

## House Cleaning

- No post-exploitation persistence left on target
- Exploit did not require uploads beyond shell payload

---

## Post-Exploitation

### Credentials & Flags

- `User.txt`: `0c4f3a9386dba985686ce78e58237c6d`  
- `Root.txt`: `b6b9cccdf6904e9ffdb0110122a50a43`

---

## Tools Utilized

* Nmap
* Python (customized ExploitDB script)
* Metasploit (initial attempt)

---

## Key Takeaways

* EternalBlue remains a notorious legacy vulnerability
* This box was extremely straightforward, with exploitation depending on manually patched scripts
* Sometimes modern tools fail on old exploits—manual modification and understanding of payloads is essential