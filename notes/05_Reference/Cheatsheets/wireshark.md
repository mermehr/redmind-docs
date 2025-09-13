---
title: Wireshark
category: Reference
tags: [tool, pcap, wireshark, cheatsheet]
---

# Wireshark

[Wireshark](https://www.wireshark.org/) is a well-known packet analyzer that comes pre-installed in nearly all  penetration testing Linux distributions. It features a powerful [filter engine](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) that allows for efficient searching through both live and captured network traffic. Some basic but useful filters include:

| Wireshark filter                                  | Description                                                  |
| ------------------------------------------------- | ------------------------------------------------------------ |
| `ip.addr == 56.48.210.13`                         | Filters packets with a specific IP address                   |
| `tcp.port == 80`                                  | Filters packets by port (HTTP in this case).                 |
| `http`                                            | Filters for HTTP traffic.                                    |
| `dns`                                             | Filters DNS traffic, which is useful to monitor domain name resolution. |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0`        | Filters SYN packets (used in TCP handshakes), useful for detecting scanning or connection attempts. |
| `icmp`                                            | Filters ICMP packets (used for Ping), which can be useful for reconnaissance or network issues. |
| `http.request.method == "POST"`                   | Filters for HTTP POST requests. In the case that POST requests are  sent over unencrypted HTTP, it may be the case that passwords or other  sensitive information is contained within. |
| `tcp.stream eq 53`                                | Filters for a specific TCP stream. Helps track a conversation between two hosts. |
| `eth.addr == 00:11:22:33:44:55`                   | Filters packets from/to a specific MAC address.              |
| `ip.src == 192.168.24.3 && ip.dst == 56.48.210.3` | Filters traffic between two specific IP addresses. Helps track communication between specific hosts. |