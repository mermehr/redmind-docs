# Month 02 Summary: July 2025

## 🔍 Red Team Progress

### HTB Boxes Completed
- **Forest** – Full Active Directory compromise via Kerberoasting and group abuse.  
- **Cap** – IDOR leading to `.pcap` exposure, FTP creds → privilege escalation via Python binary.  
- **Netmon** – EternalBlue + PRTG command injection.  
- **Nibbles** – Default creds on `nibbleblog` → reverse shell upload → local script privesc.  
- **TwoMillion** – API endpoint enumeration, JavaScript analysis → object traversal privesc.  
- **Jerry** – Apache Tomcat Metasploit classic.  
- **Legacy** – EternalBlue success.  
- **Blue (Revisited)** – Diagnosed shell issues and corrected Metasploit exploit logic.

### HTB Practice Boxes (No Reports)
- `explosion`, `preignition`, `mongod`, `synced`, `ignition`, `bike`, `Funnel`, `pennyworth`, `tactics`, `included`, `markup`, `base`

### HTB Challenges Completed
- **Crypto/Rev/DIFR**: `The Last Dance`, `Simple Encryptor`, `BabyEncryption`, `Brutus`  
- **Web**: `Flag Command`, `Spookifier`, `Pdfy`, `Criticalops`  
- **Sherlock**: `SpookPass`, `Unit42`, `Campfire-1/2`, `JinjaCare`, `NeoVault`

### Techniques Practiced
- Enumeration: SMB, MongoDB, Jenkins, Rsync, Tomcat, NodeJS  
- Exploitation: EternalBlue, XXE, SSTI, default creds, IDOR, API auth bypass, file uploads  
- Privilege Escalation: custom scripts, cron jobs, capability abuse, misconfigurations  
- Tooling fluency: Metasploit, BloodHound, Wireshark, Burp, enum4linux, ldapsearch

---

## 🐍 Python Development

### ATBS Progress (Automate the Boring Stuff)
- ✅ Chapters 4–11 completed
- Topics: functions, exceptions, dictionaries, file I/O, regex, filesystem automation

### Scripts Created
- `phoneAndEmail.py`, `strong-password-check.py`, `quiz-generator.py`, `mad-libs.py`,  
  `regex-search.py`, `xor_stream_reuse_recover.py`, `rename_dates.py`, `find_large_files.py`,  
  `renumber_files.py`, `selective_copy.py`, `backup-to-zip.py`

### Skills Strengthened
- File operations, path traversal, string processing  
- Regex extraction, text search automation  
- Modular scripting and offensive utility creation  
- Transition from syntax learning to tool development

---

## 📘 OSCP / PWK Study

- Covered:
  - Public exploits (EternalBlue deep dive)  
  - File upload & directory traversal  
  - Payload generation (Chapter 20)  
  - Vulnerability scanning techniques (Nessus, Nmap, OpenVAS)  
  - AD privilege escalation (Chapters 21–22)  
  - Final shift away from linear PWK reading — now pursuing targeted, skill-based deep dives

---

## 🛠️ Tooling & Workflow

- Tools Mastered: Metasploit, linPEAS, BloodHound, Gobuster, Burp Suite  
- Common practice flow: enumeration → initial access → local recon → privesc → post-exploitation  
- Weekly journaling formalized into GitHub pipeline, linking reports, scripts, and reflections

---

## 🧭 Key Takeaways

- Active Directory exploitation (Forest) marked a major milestone in operational confidence  
- Python is now integral to your workflow — replacing manual tasks and enhancing recon/exploitation  
- Legacy boxes and revisits offered powerful troubleshooting reps and reverse engineering practice  
- Shifting from linear study to purpose-driven projects is paying off in clarity, retention, and velocity  
- Tool fluency and mental models are rapidly solidifying — the gap between theory and practice is shrinking