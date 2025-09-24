---
edit: Need to update and edit
---

# Windows powershell commands

## Web

```powershell
# curl -I alternative
Invoke-WebRequest -Uri "https://website-to-visit" -Method GET

# wget alternative
Invoke-WebRequest -Uri "https://website-to-visit\file.ps1" -OutFile "C:\<filename>"

# Using .NET
(New-Object
Net.WebClient).DownloadFile("https://website-to-visit\tools.zip", "Tools.zip")
```

## Enumeration

```powershell
# Local users and groups
Get-LocalUser
get-localgroup

# Random
Get-LocalUser administrator | get-member
Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled

# AD users
Get-ADUser -Filter *

# Services
Get-Service | Select-Object -Property *
Get-Service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | 
Get-Service | where DisplayName -like '*Defender*' | Select-Object -Property *

# Remote query of a hosts services
Get-service -ComputerName ACADEMY-ICL-DC
```

## Loot folders

```powershell
# Show hidden
Get-ChildItem -Hidden

# Administrator and interesting files
# Admin console history
C:\Users<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
Get-Content (Get-PSReadlineOption).HistorySavePath

# dont forget to check
\AppData\
```

## Searching for loot

```powershell
# Count number of files
(Get-ChildItem -File -Recurse | Measure-Object).Count

# Search rec for a specific file
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

# Grep like
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!

# Searcha dir and for a file type
Get-ChildItem -Path /home/jon/ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}

Get-ChildItem -Path /home/jon/ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}

# Look for passwords in file types, like grep
Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | sls "Password","credential","key"

# Combined
Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"

```

## Sheduled tasks

```powershell
# Allows for the creation of scheduled tasks
schtasks /create

schtasks /create /sc <Schedule Frequency> /tn <TaskName> /tr <ProgramPath>

# Modification of an existing scheduled task
schtasks /change /tn <Task Name> /ru <Username> /rp <Password>

# Delete
schtasks /delete /tn <Task Name>
```

