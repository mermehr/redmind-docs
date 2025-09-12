---
title: File Cracking
tags: [hash, password, cracking, file, ssh]
tools: ['john', 'openssl', 'hashcat', 'openssl', 'dislocker']
---

# File Cracking

## Hunting for Encrypted Files

[FileInfo](https://fileinfo.com/filetypes/encoded) - Reference list

### Finding encrypted files | ssh keys

```bash
# Common encryted files
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search for ssj keys by header
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# Check if ssh key in encrypted
ssh-keygen -yf ~/.ssh/id_ed25519
```

### Encrypted ssh key w/ ssh2john

`````
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash

john ssh.hash --show
`````

### Password-protected documents w/ office2john

`````
# Office files
office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash

john protected-docx.hash --show

# PDf files
pdf2john.py PDF.pdf > pdf.hash
`````

## Protected Archives

Grab the file extension list if needed:

`curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt`

### Zip files w/ zip2john

`````
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

john zip.hash --show
`````

### OpenSSL encrypted GZIP files w/ openssl

`````
# Find encryption format
file GZIP.gzip
GZIP.gzip: openssl enc'd data with salted password

# Use for loop and openssl to crack password.
# If found, check dir for newly created files
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
`````

### BitLocker-encrypted drives w/ bitlocker2john

```bash
# Cracking the password using the first hash ($bitlocker$0$)
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash

# Cracking with hashcat, prepair for a long run
hashcat -a 0 -m 22100 '<HASH>' /usr/share/wordlists/rockyou.txt
```

#### Mounting bitlocker in linux

`````
# Install dislocker
sudo apt-get install dislocker

# Make folders
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount

# Losetup to configure the VHD as loop device, decrypt the drive using dislocker
sudo losetup -f -P Backup.vhd
sudo dislocker /dev/loop0p2 -u<PASSWD> -- /media/bitlocker

# Mount and unmount
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
`````

