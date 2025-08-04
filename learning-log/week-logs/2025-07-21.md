# Week 06 Summary: July 21 – July 27, 2025

## 🧠 Red Team Progress

### HTB Boxes Completed
- ✅ **Cap** – IDOR vulnerability exposed `.pcap` data with FTP credentials. Used Wireshark to analyze traffic, leading to initial access and root via Python binary with `cap_setuid` capability.  
- ✅ **Netmon** – Leveraged known exploit (EternalBlue variant) to gain access. Reviewed Metasploit modules and exploited a PRTG command injection vector. Full report created.

### HTB Practice Boxes (No Reports)
- `explosion`, `preignition`, `mongod`, `synced`, `ignition`, `bike`, `Funnel`, `pennyworth`, `tactics`, `included`, `markup`, `base`
- Techniques covered: weak creds, SSTI, Rsync exposure, XXE injection, Jenkins RCE, auth bypass, custom app exploitation
- Services targeted: FTP, RDP, SMB, Apache, MongoDB, Rsync, Magento, NodeJS, PostgreSQL, LXD, sudo misconfig

### HTB Challenges Completed
- `SpookPass` (Reverse)
- `The Last Dance` (Crypto)
- `Low Logic` (Hardware)
- `Flag Command` (Web)
- `Spookifier` (Web)
- `Brutus` (DIFR)

### PWK Progress
- **Chapter 15 – Public Exploits** (EternalBlue)
- **Chapter 14.5 – File Upload Vulns**
- **Chapter 20 – Metasploit & Payload Generation**

## 🐍 Python Practice – ATBS Progress

### Chapters Covered
- ✅ Chapter 8 – String Manipulation (completed)
- ✅ Chapter 9 – Regular Expressions (completed)
  - Concepts: character classes, quantifiers, greedy vs non-greedy matching, grouping, extraction, search methods

### Scripts Created
- ✅ `pigLat.py` – English to Pig Latin CLI translator  
- ✅ `tablePrinter.py` – Dynamic column-based table formatter  
- ✅ `phoneAndEmail.py` – Regex-driven data scraper  
- ✅ `xor_stream_reuse_recover.py` – XOR stream key recovery utility  
- ✅ `strong-password-check.py` – Regex-based password strength tester  

### Skills Strengthened
- Regex pattern writing and logic chaining  
- Input transformation and text parsing  
- Real-world automation scripts for offensive tooling  
- Unicode, string slicing, and formatting

## ⚙️ Tools Practiced
- **Red Team**: Nmap, Wireshark, LinPEAS, Metasploit, Gobuster, Burp Suite  
- **Python**: Regex module, `re.findall()`, file reading/writing, string formatting, scripting pipelines

## 🧠 Key Takeaways
- Cap provided a great walkthrough of chaining passive recon (IDOR + pcap) into privilege escalation using Linux capabilities.
- Practice boxes served as a broad sandbox for sharpening exploit pattern recognition across multiple protocols and services.
- Python is now being leveraged for real tooling—regex mastery is paying off in automation and pattern analysis tasks.
- Enumeration is becoming instinctive, and scripts are starting to slot into reusable offensive workflows.
