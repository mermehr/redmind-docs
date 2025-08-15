# Footprinting module

**Interesting Links:**

- [The SolarWinds Cyberattack](https://www.rpc.senate.gov/policy-papers/the-solarwinds-cyberattack)
- [Certificate Fingerprinting](https://crt.sh/)
- [Grey Hat Warefare](https://buckets.grayhatwarfare.com/)

**Intresting Items:**

- Found at random @inlanefreight.com with `dig` - HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}

**Rpcsclient:**

Brute force user RIDS:
for i in $(seq 500 1100);do rpcclient -N -U "" $htb -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

**NFS file escalation:**

>We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the SUID of that user and then run the shell via the SSH user.

**DNS** - Do a return on this

- Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain.
  - `ns.inlanefreight.htb`
- Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...})
  - `HTB{DN5_z0N3_7r4N5F3r_iskdufhcnlu34}`
- What is the IPv4 address of the hostname DC1?
  - `10.129.34.16`
- What is the FQDN of the host where the last octet ends with "x.x.x.203"?
  - `win2k.dev.inlanefreight.htb`

**SNMP:**

- Enumerate the SMTP service and submit the banner, including its version as the answer.
  - `InFreight ESMTP v2.11`
- Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer.
  - `robin`

**IMAP/POP3:**

[CRIB IMAP Commands](https://donsutherland.org/crib/imap)

- Figure out the exact organization name from the IMAP/POP3 service and submit it as the answer.
  - `InlaneFreight Ltd`
- What is the FQDN that the IMAP and POP3 servers are assigned to?
  - `dev.inlanefreight.htb`
- Enumerate the IMAP service and submit the flag as the answer. (Format: HTB{...})
  - `HTB{roncfbw7iszerd7shni7jr2343zhrj}`
- What is the customized version of the POP3 server?
  - `InFreight POP3 v9.188`
- What is the admin email address?
  - `devadmin@inlanefreight.htb`
- Try to access the emails on the IMAP server and submit the flag as the answer. (Format: HTB{...})
  - `HTB{983uzn8jmfgpd8jmof8c34n7zio}`
