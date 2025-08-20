# Virtual Host Discovery

>Virtual host discovery can generate significant traffic and might be detected by intrusion detection systems (IDS) or web application firewalls (WAF). Exercise caution and obtain proper authorization before scanning any targets.

**General:**

`gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain`

**Append IP to domain:**

`gobuster vhost -u http://94.237.49.23:57852 --domain inlanefreight.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain`

**Certificate Lookup:**

`curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u`

---

## Tools

| Tool | Description | Features |
| --- |  --- |  --- |
| [gobuster](https://github.com/OJ/gobuster) | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility. | Supports recursion, wildcard discovery, and various filters. |
| [ffuf](https://github.com/ffuf/ffuf) | Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header. | Customizable wordlist input and filtering options. |