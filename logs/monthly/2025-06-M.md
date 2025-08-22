# Month 01 Summary: June 13 – July 12, 2025

## 🔍 Red Team Progress

### Boxes Completed
- **VulnHub:** DC:1, Escalate My Privileges 1
- **Hack The Box:**
  - Small MySQL vuln box
  - FTP Breach, S3 Shell, WinRM/NTLMv2 Chain
  - Archetype (MSSQL → Impacket → WinPEAS)
  - Lame (Samba RCE CVE-2007-2447)
  - Bashed (cronjob privesc)
  - Unified (Log4Shell → MongoDB)
  - Vaccine (ZIP crack → SQLMap → GTFOBins)
  - Shocker (CVE-2014-6271, Meterpreter)
  - Optimum (HFS CVE → bfill.exe privesc)
  - Blue (insecure SMB)
  - Cronos (SQLi → Burp RCE → cronjob privesc)

### Techniques Practiced
- Enumeration (enum4linux, Burp, Nmap, smbclient)
- Privilege escalation: cronjobs, scheduled tasks, GTFOBins
- Shell stabilization (e.g., `pty.spawn`, Metasploit payloads)
- Post-exploitation: credential capture, service chaining
- Payload creation and chaining (Metasploit, msfvenom, manual)
- Fluency with both Linux and Windows toolkits

## 🐍 Python Development

- **MOOC Completed:** Parts 1–4
  - Control structures, regex, nested functions, recursion
  - Transitioned away after diminishing returns
- **Switched to ATBS (Al Sweigart):**
  - Read to pg. 82 (Chapter 7), focused on dictionaries and I/O logic
  - Projects for CLI data processing, board states, inventory logic
- Practical use for scripting enumeration, loop control, automation

## 🧠 OSCP / PWK Study

- Covered:
  - Manual enumeration, vuln scanning, web attacks (BurpSuite)
  - Exploit dev (tested on DC:2)
  - Exploit chaining based on banners and service recognition
  - Windows privesc methodology (manual vs automated)
  - Payload generation, bad char handling, msfvenom flags

### Core Alignment
- PWK methodologies applied directly to HTB/VulnHub boxes
- Learning reinforced through hands-on simulation, not passive reading

## 🛠️ Tooling & Infrastructure

- Built internal lab:
  - AD lab via QEMU (Windows Server, Kali, clients)
  - Isolated sandbox environments for safe testing
- Optimization:
  - Recompiled tools like John/Nmap for GPU
  - Streamlined bash/Nmap wrappers and regex-based recon parsers

## 🧭 Key Takeaways

- Hands-on workflow beats passive study; boxes solidify theory
- Python is now a useful tool, not just an academic hurdle
- Tools are becoming second-nature (Burp, Metasploit, linPEAS)
- Logs and scripting enhance retention and build mental models
- Switching from MOOC to more purposeful scripting re-energized learning
