## Day Log - July 13th, 2025

## Goals
- [ ] Finish Zeek DNS module on TryHackMe
- [ ] Review Suricata logging options

## What I Learned
- Observed differences between `dns.log` and `conn.log`.
- Learned how to filter `conn.log` entries by port.

## Commands Sample
```bash
zeek -Cr sample.pcap
cat conn.log | zeek-cut id.orig_h id.resp_h
<!--stackedit_data:
eyJoaXN0b3J5IjpbLTEyNDc4NDE5MjldfQ==
-->