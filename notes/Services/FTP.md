---
title: FTP
tags: [service, enum]
service: FTP
protocol: ['tcp']
port: [21]
auth: ['anonymous', 'password', 'tls-auth']
tools: ['nmap', 'ftp', 'hydra', 'medusa']
notes: "Check anonymous login, weak creds, cleartext vs AUTH TLS"
---

# File Transfer Protocol

## Common Attack Paths

### Enumeration
- [ ] Check for anonymous login → `ftp <target>`
- [ ] Banner grab → `nc <target> 21`
- [ ] Recursive directory listing → `ls -R`
- [ ] Nmap NSE → `nmap --script=ftp* -p21 <target>`

### Attack Paths
- Anonymous login → file leaks / upload webshells
- Weak passwords → brute force via hydra/medusa
- Cleartext creds over network → sniff with Wireshark/tcpdump
- Exploits in old vsftpd / ProFTPD versions

### Auxiliary Notes
- Try uploading test files if permissions allow.
- Watch for writable web roots (easy shell).
- Passive vs active FTP can matter in firewalled labs.



## General Enumeration

*Common Commands:*

```bash
sudo nmap -sV -p21 -sC -A 10.129.14.136

# Find NSE Scripts
find / -type f -name ftp\* 2>/dev/null | grep scripts

# Pilage all files
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```

## Command Reference

### FTP Command Line

| Type | Command | What it Does |
| --- |  --- |  --- |
| Command Line | \-v | Suppresses verbose display of remote server responses. |
| Command Line | \-n | Suppresses auto login |
| Command Line | \-i | Turns off interactive prompting during multiple file transfers. |
| Command Line | \-d | Enables debugging, displaying all ftp commands passed between the client and server. |
| Command Line | --g | Disables filename globbing, which permits the use of wildcard chracters in local file and path names. |
| Command Line | \-s:filename | Specifies a text file containing ftp commands; the commands will automatically run after ftp starts. No spaces are allowed in this parameter. Use this switch instead of redirection (>). |
| Command Line | \-a | Use any local interface when binding data connection. |
| Command Line | \-w:windowsize | Overrides the default transfer buffer size of 4096. |
| Command Line | \-computer | Specifies the computer name or IP address of the remote computer to connect to. The computer, if specified, must be the last parameter on the line. |

### FTP Command List

| Type | Command | What it Does |
| --- |  --- |  --- |
| Command | ! | Runs the specified command on the local computer |
| Command | ? | Displays descriptions for ftp commands |
| Command | append | Appends a local file to a file on the remote computer |
| Command | ascii | Sets the file transfer type to ASCII, the default |
| Command | bell | Toggles a bell to ring after each file transfer command is completed (default = OFF) |
| Command | binary | Sets the file transfer type to binary |
| Command | bye | Ends the FTP session and exits ftp |
| Command | cd | Changes the working directory on the remote computer |
| Command | close | Ends the FTP session and returns to the command interpreter |
| Command | debug | Toggles debugging (default = OFF) |
| Command | delete | Deletes a single file on a remote computer |
| Command | dir | Displays a list of a remote directoryâ€™s files and subdirectories |
| Command | disconnect | Disconnects from the remote computer, retaining the ftp prompt |
| Command | get | Copies a single remote file to the local computer |
| Command | glob | Toggles filename globbing (wildcard characters) (default = ON) |
| Command | hash | Toggles hash sign (#) printing for each data block transferred (default = OFF) |
| Command | help | Displays descriptions for ftp commands |
