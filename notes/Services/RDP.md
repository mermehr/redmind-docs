---
title: RDP
tags: [service, enum, windows]
service: RDP
protocol: ['tcp']
port: [3389]
auth: ['password', 'ntlm', 'kerberos', 'certificate']
tools: ['nmap', 'xfreerdp', 'rdpscan', 'hydra']
notes: "Brute force creds; test for BlueKeep, CredSSP, and weak NLA"
---

# Remote Desktop Protocol

## Common Attack Paths

### Enumeration
- [ ] Nmap script → `nmap -p3389 --script=rdp* <target>`
- [ ] Banner grab → `rdpscan <target>`

### Attack Paths
- Brute force → hydra/medusa
- Exploits → BlueKeep (CVE-2019-0708), DejaBlue
- Pass-the-Hash / Kerberos ticket login
- Weak NLA configurations → bypasses

### Auxiliary Notes
- Often brute force is noisy; use carefully.
- Check screenshots (xfreerdp) to confirm access.
- RDP logs can alert admins quickly.



## General Enumeration

*Common Commands:*
`nmap -sV -sC 10.129.201.248 -p3389 --script rdp*`

*Trace for security - Threat hunters can find the scripts:*
`nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n`

### RDP Security Check - Installation & Check

```bash
sudo cpan
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl 10.129.201.248
```

*Initiate an RDP Session*
`xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248`

`xfreerdp +clipboard /size:1920x1060 /u:Administrator /p:xxx /v:n.n.n.n`