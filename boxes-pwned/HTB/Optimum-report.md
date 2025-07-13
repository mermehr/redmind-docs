# Red Team Engagement Log – HTB: Optimum

## Engagement Overview
**Target:** Optimum  
**Box IP:** 10.10.10.8  
**Local Attacker IP:** 10.10.16.10  
**Operating System:** Windows Server 2012 R2 Standard  
**Date:** 2025-07-09

---

### Objectives
- Gain reverse shell on target Windows box
- Perform local privilege escalation to SYSTEM
- Capture user and root flags
- Practice Windows exploit methodology with Metasploit and manual post-exploitation

---

## Service Enumeration
- **Port 80/tcp** open  
  - Service: **HttpFileServer (HFS) 2.3**  
  - Known vulnerable to **CVE-2014-6287**

---

## Methodologies

### Initial Access
- Used Metasploit module:  
  `exploit/windows/http/rejetto_hfs_exec`
- Reverse shell established via Meterpreter
- Shell access gained as user: `optimum\kostas`

### Privilege Escalation
- Enumeration revealed vulnerable patch level
- Used **Windows Exploit Suggester** → identified **MS16-098** (CVE-2016-3309)
- Uploaded `bfill.exe` (compiled local exploit)
- Executed successfully, obtained SYSTEM privileges:
  ```bash
  whoami → nt authority\system
  ```

---

## House Cleaning
- Captured user and root flags
- Minimal footprint left on target system
- Removed tools where possible (bfill.exe, temporary payloads)

---

## Post-Exploitation

### Tools Utilized
- `nmap`
- `metasploit`
- `searchsploit`
- `Windows-Exploit-Suggester`
- `bfill.exe` (local privesc binary)

---

### Flags Captured
- **User Flag:** `7272064e53427073b00fea81d6962ed8`
- **Root Flag:** `da6f444b14dee2a601c862d852ac9788`

---

### Key Takeaways
- Reinforced knowledge of Windows privilege escalation via kernel exploits.
- Demonstrated effective use of Metasploit for both RCE and shell handling.
- Validated a structured workflow: enumeration → exploitation → escalation → cleanup.
- Real-world applicability of CVE identification and targeted tool deployment.