---
title: WMI
tags: [service, enum, windows, lateral]
service: WMI
protocol: ['tcp']
port: [135]
auth: ['ntlm', 'kerberos']
tools: ['wmiexec.py', 'impacket', 'evil-winrm']
notes: "Useful for lateral movement, remote command execution"
---

# Windows Management Instrumentation

## Common Attack Paths

### Enumeration
- [ ] Test with CrackMapExec → `cme winrm <target> -u user -p pass`
- [ ] Banner grab → `nc <target> 5985`

### Attack Paths
- Valid domain creds → remote shell with Evil-WinRM
- Kerberos ticket abuse for auth
- Certificate-based authentication

### Auxiliary Notes
- One of the cleanest ways to get shell on Windows with creds.
- Often used by admins, so less suspicious traffic.



## General Enumeration

*Common Commands:*

`wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"`

### Service Information

Windows Management Instrumentation (`WMI`) is Microsoft's implementation and also an extension of the Common Information Model (`CIM`), core functionality of the standardized Web-Based Enterprise Management (`WBEM`) for the Windows platform. WMI allows read and write access to almost all settings on Windows systems. Understandably, this makes it the most critical interface in the Windows environment for the administration and remote maintenance of Windows computers, regardless of whether they are PCs or servers. WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (`WMIC`). WMI is not a single program but consists of several programs and various databases, also known as repositories.

