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
