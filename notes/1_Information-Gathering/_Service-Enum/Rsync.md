### Footprinting:

`$ sudo nmap -sV -p 873 127.0.0.1`

### Probing for Accessible Shares:

`nc -nv 127.0.0.1 873`

### Enumerating an Open Share

`$ rsync -av --list-only rsync://127.0.0.1/dev`