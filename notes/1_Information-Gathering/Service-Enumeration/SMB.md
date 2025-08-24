---
title: "Server Message Block"
date: 2025-08-23
tags: [smb, rcpclient, smbclient, smbmap service]
port: [tcp, 445, 137, 138, 139]
---

# Server Message Block

## Enumeration

*Common Commands*

`sudo nmap 10.129.14.128 -sV -sC -p139,445`

#### SMBClient

*List Shares:*

`smbclient -N -L //10.129.14.128`

*Connect to share:*

`smbclient //10.129.14.128/notes`

### RPCclient

`rpcclient -U "" 10.129.14.128`

*Commands:*

| Query | Description |
| --- |  --- |
| srvinfo | Server information. |
| enumdomains | Enumerate all domains that are deployed in the network. |
| querydominfo | Provides domain, server, and user information of deployed domains. |
| netshareenumall | Enumerates all available shares. |
| netsharegetinfo <share> | Provides information about a specific share. |
| enumdomusers | Enumerates all domain users. |
| queryuser <RID> | Provides information about a specific user. |

### Brute Forcing User RIDs

`
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\\n' $i)" | grep "User Name\\|user\_rid\\|group\_rid" && echo "";done
`

### Impacket - Samrdump.py

`
samrdump.py 10.129.14.128
`

### SMBmap

`smbmap -H 10.129.14.128`

### Enum4Linux-ng - Enumeration

`./enum4linux-ng.py 10.129.14.128 -A`