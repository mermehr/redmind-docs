### Dont forget:

chmod 600 id\_rsa

ssh user@$htb -i id\_rsa

### Footprinting:

### SSH-Audit:

`$ git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit`

`./ssh-audit.py 10.129.14.132`

One of the tools we can use to fingerprint the SSH server is [ssh-audit](https://github.com/jtesta/ssh-audit). It checks the client-side and server-side configuration and shows some general information and which encryption algorithms are still used by the client and server. Of course, this could be exploited by attacking the server or client at the cryptic level later.

### Change Authentication Method - brute force:

`$ ssh -v cry0l1t3@10.129.14.132`

$ `ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password`