Most scanning tools have a timeout set until they receive a response from the service. If this tool does not respond within a specific time, this service/port will be marked as closed, filtered, or unknown. In the last two cases, we will still be able to work with it. However, if a port is marked as closed and Nmap doesn't show it to us, we will be in a bad situation. This service/port may provide us with the opportunity to find a way to access the system. Therefore, this result can take much unnecessary time until we find it.

nmap host discovery:
sudo nmap 10.129.2.0/24 -sn -o tnet | grep for | cut -d" " -f5

links:
https://nmap.org/book/host-discovery-strategies.html
https://nmap.org/book/man-port-scanning-techniques.html
https://www.f5.com/pdf/white-papers/sctp-introduction-wp.pdf

take aways:
