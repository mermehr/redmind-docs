## Awk

This command extracts usernames from the `/etc/passwd` file, showcasing awk's ability to process structured text data.

```bash
awk -F ':' '{print $1}' /etc/passwd

# Alt

cut -d: -f1 /etc/passwd
```

Count the number of unique IP addresses:

```bash
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr
```

## Grep

This command recursively searches for the term ‘ERROR’ in all files, demonstrating grep's text-searching prowess.

```
grep -r 'ERROR' /var/log/
```

## Find

This command searches the file system for root suid, ouputs errors to null

```bash
find / -perm -4000 -type f 2>/dev/null
```

This command locates files `/path/to/dir` modified in the last 24 hours, demonstrating the find's capability to search based on criteria.

```
find /path/to/dir -type f -mtime -1
```

## Open ports

Searching for open ports.

```bash
nmap -p 1-100 localhost | grep 'open' | awk '{print $1, $3}'
```



Here, grep, awk, and sort collaborate to list and organize open ports, providing valuable insights into system security.

```
netstat -tuln | grep 'LISTEN' | awk '{print $4}' | sort
```

