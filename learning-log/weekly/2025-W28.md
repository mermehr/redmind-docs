# Week 05 Summary: July 13 – July 20, 2025

## 🧠 Red Team Progress

### HTB Boxes Completed
- ✅ **Forest** – Full AD compromise using Kerberoasting, BloodHound analysis, and group membership abuse. Applied PWK Chapters 21–22 in depth.
- ✅ **Nibbles** – Default creds on `/nibbleblog`, PHP reverse shell upload, privilege escalation via custom script owned by root.

### PWK Progress
- **Chapter 7 – Vulnerability Scanning**
  - Compared authenticated vs. unauthenticated scans
  - Tools: Nessus, OpenVAS, Nmap NSE, Nikto
  - Concepts: false positives, plugin tuning, scan scope
- **Chapter 8 – Web App Attacks**
  - Tools: Wappalyzer, Gobuster, Burp Suite, browser dev tools
  - Covered: content discovery, HTTP inspection, XSS basics
- Concepts reinforced:
  - Active Directory architecture and abuse paths
  - NTLM/Kerberos flaws (AS-REP Roasting, PTH, PTT)
  - Scanning posture and safety in live environments

## 🐍 Python Practice – ATBS Progress

### Chapters Covered
- Chapter 4–7 (Exceptions, Functions, Lists, Dictionaries)
- Built custom scripts to reinforce concepts:
  - ✅ Coin flip streak simulator (probability modeling)
  - ✅ Comma Code (list formatter)
  - ✅ CLI Chessboard (dictionary-based board state + validation)
  - ✅ RPG Inventory Tracker (inventory merging + accumulator pattern)

### Skills Strengthened
- `try/except`, scope and return handling
- List slicing, `enumerate()`, tuple unpacking
- Dictionary modeling, command parsing, text templating
- Automation logic and user-driven interaction

## ⚙️ Tools Practiced
- **Red Team**: BloodHound, SharpHound, Mimikatz, Rubeus, enum4linux, ldapsearch, Burp Suite, Gobuster
- **Python**: PyCharm IDE, debugger, string formatting, randomness, CLI interaction

## 🧠 Key Takeaways
- Forest marked a major milestone in mastering AD attacks under pressure
- Nibbles reinforced real-world web → local privesc chain
- Python is transitioning from syntax practice to functional tool-building
- Vulnerability scanning and web app enumeration now grounded in theory + practice