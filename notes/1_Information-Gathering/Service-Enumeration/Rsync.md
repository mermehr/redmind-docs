---
title: "Rsynce"
date: 2025-08-23
tags: [rsycn, service]
port: [tcp, 873, 22]
---

# Rsync

## Enumeration

*Common Commands:*

`$ sudo nmap -sV -p 873 127.0.0.1`

*Probing for Accessible Shares:*

`nc -nv 127.0.0.1 873`

*Enumerating an Open Share*

`$ rsync -av --list-only rsync://127.0.0.1/dev`