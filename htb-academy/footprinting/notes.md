# Footprinting module

**Interesting Links:**

- [The SolarWinds Cyberattack](https://www.rpc.senate.gov/policy-papers/the-solarwinds-cyberattack)
- [Certificate Fingerprinting](https://crt.sh/)
- [Grey Hat Warefare](https://buckets.grayhatwarfare.com/)
- [Crunch Wordlist Generator](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en)
- [Introduction To SQL](HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g})
- [MySQL Reference Manual](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The%20mysql%20schema%20is%20the,used%20for%20other%20operational%20purposes)
- [SQL*Plus Commands](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985)

**Intresting Items:**

- Found at random @inlanefreight.com with `dig` - HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}

**Rpcsclient:**

Brute force user RIDS:
`for i in $(seq 500 1100);do rpcclient -N -U "" $htb -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`

**NFS file escalation:**

>We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the SUID of that user and then run the shell via the SSH user.

**DNS** - Do a return on this

- ***Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.***
  - `ns.inlanefreight.htb`
- ***Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...})***
  - `HTB{--SNIP--}`
- ***What is the IPv4 address of the hostname DC1?***
  - `10.129.34.16`
- ***What is the FQDN of the host where the last octet ends with "x.x.x.203"?***
  - `win2k.dev.inlanefreight.htb`

**SNMP:**

- ***Enumerate the SMTP service and submit the banner, including its version as the answer.***
  - `InFreight ESMTP v2.11`
- ***Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer***.
  - `robin`

**IMAP/POP3:**

[CRIB IMAP Commands](https://donsutherland.org/crib/imap)

- ***Figure out the exact organization name from the IMAP/POP3 service and submit it as the answer.***
  - `InlaneFreight Ltd`
- ***What is the FQDN that the IMAP and POP3 servers are assigned to?***
  - `dev.inlanefreight.htb`
- ***Enumerate the IMAP service and submit the flag as the answer. (Format: HTB{...})***
  - `HTB{--SNIP--}`
- ***What is the customized version of the POP3 server?***
  - `InFreight POP3 v9.188`
- ***What is the admin email address?***
  - `devadmin@inlanefreight.htb`
- ***Try to access the emails on the IMAP server and submit the flag as the answer. (Format: HTB{...})***
  - `HTB{--SNIP--}`

**SNMP:**

- ***Enumerate the SNMP service and obtain the email address of the admin. Submit it as the answer.***
  - `devadmin@inlanefreight.htb`
- ***What is the customized version of the SNMP server?***
  - `InFreight SNMP v0.91`
- ***Enumerate the custom script that is running on the system and submit its output as the answer.***
  - `HTB{--SNIP--}`

**MySQL:**

- ***Enumerate the MySQL server and determine the version in use. (Format: MySQL X.X.XX)***
  - `MySQL 8.0.27`
- ***During our penetration test, we found weak credentials "robin:robin". We should try these against the MySQL server. What is the email address of the customer "Otto Lang"?***
  - `ultrices@google.htb`
  
**MSSQL:**

- ***Enumerate the target using the concepts taught in this section. List the hostname of MSSQL server.***
  - `ILF-SQL-01`
- ***Connect to the MSSQL instance running on the target using the account (backdoor:Password1), then list the non-default database present on the server.***
  - `Employees`
  
**Oracle TNS:**

- ***Enumerate the target Oracle database and submit the password hash of the user DBSNMP as the answer.***
  - `E066D214D5421CCC`

**IPMI:**

| IPMI | user | pass |
| ---- | ---- | ---- |
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized |
| Supermicro IPMI | ADMIN | ADMIN |

- ***What username is configured for accessing the host via IPMI?***
  - `admin`
- ***What is the account's cleartext password?***
  - `trinity`

>Remote management services can provide us with a treasure trove of data and often be abused for unauthorized access through either weak/default credentials or password re-use. We should always probe these services for as much information as we can gather and leave no stone unturned, especially when we have compiled a list of credentials from elsewhere in the target network.

**End of module challenges:**

- ***Enumerate the server carefully and find the flag.txt file. Submit the contents of this file as the answer.***
  - `HTB{--SNIP--7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}`
- ***Enumerate the server carefully and find the username "HTB" and its password. Then, submit this user's password as the answer.***
  - `--SNIP--dn43i7AoqVPK4zWR`
- ***Enumerate the server carefully and find the username "HTB" and its password. Then, submit HTB's password as the answer.***
  - `--SNIP--zse7rzhnckhssncif7ds`
