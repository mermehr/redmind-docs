# Services Index

A quick-reference index of all services, ports, and common auth vectors.

| Service                     | Ports           | Protocol | Auth Options                     | Tags                            |
| --------------------------- | --------------- | -------- | -------------------------------- | ------------------------------- |
| [DNS](Services/DNS.md)              | 53              | udp,tcp  | none                             | service, enum                   |
| [FTP](Services/FTP.md)               | 21              | tcp      | anonymous, password, tls-auth    | service, enum                   |
| [IMAP/POP3](Services/IMAP-POP3.md)   | 110,143,993,995 | tcp      | password, starttls, ssl/tls      | service, enum, mail             |
| [IPMI](Services/IPMI.md)             | 623             | udp,tcp  | default-creds, password, cipher0 | service, enum                   |
| [MSSQL](Services/MSSQL.md)           | 1433            | tcp      | password, ntlm, kerberos, sa     | service, enum, database         |
| [MySQL](Services/MySQL.md)           | 3306            | tcp      | password, default-creds, socket  | service, enum, database         |
| [NFS](Services/NFS.md)               | 2049            | udp,tcp  | none, krb5                       | service, enum, fileshare        |
| [Oracle DB](Services/ORCL.md)        | 1521            | tcp      | password, default-creds, sid     | service, enum, database         |
| [R-services](Services/R-services.md) | 512,513,514     | tcp      | trusted-hosts, cleartext         | service, enum, legacy           |
| [RDP](Services/RDP.md)               | 3389            | tcp      | password, ntlm, kerberos, cert   | service, enum, windows          |
| [Rsync](Services/Rsync.md)           | 873             | tcp      | anonymous, password              | service, enum, fileshare        |
| [SMB](Services/SMB.md)               | 139,445         | tcp      | anonymous, password, ntlm, kerb  | service, enum, windows, share   |
| [SMTP](Services/SMTP.md)             | 25,465,587      | tcp      | anonymous-relay, password, tls   | service, enum, mail             |
| [SNMP](Services/SNMP.md)             | 161             | udp      | community-strings, snmpv3        | service, enum, monitoring       |
| [SSH](Services/SSH.md)               | 22              | tcp      | password, key-based, kerberos    | service, enum, remote           |
| [WMI](Services/WMI.md)               | 135             | tcp      | ntlm, kerberos                   | service, enum, windows, lateral |
| [WinRM](Services/WinRM.md)           | 5985,5986       | tcp      | ntlm, kerberos, certificate      | service, enum, windows, remote  |

