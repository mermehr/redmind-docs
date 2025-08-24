---
title: "IMAP and POP3"
date: 2025-08-23
tags: [imap, pop3, service]
port: [tcp, 143, 993, 110, 995]
---
# IMAP and POP3

## Enumeration

*Common Commands:*

```bash
sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC

# Get banner and tls/ssl information
curl -k 'imaps://10.129.14.128' --user cry0l1t3:1234 -v

# Connecting to service
openssl s_client -connect 10.129.14.128:pop3s
openssl s_client -connect 10.129.14.128:imaps
```

*Example:*

```bash
1 LOGIN tom {password}
1 LIST "" \*
1 SELECT INBOX
1 FETCH 1 BODY\[\]
```
## Command Reference

### IMAP Commands
| Command | Description |
| --- |  --- |
| LOGIN username password | User's login. |
| LIST "" \* | Lists all directories. |
| CREATE "INBOX" | Creates a mailbox with a specified name. |
| DELETE "INBOX" | Deletes a mailbox. |
| RENAME "ToRead" "Important" | Renames a mailbox. |
| LSUB "" \* | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |
| SELECT INBOX | Selects a mailbox so that messages in the mailbox can be accessed. |
| UNSELECT INBOX | Exits the selected mailbox. |
| FETCH <ID> all | Retrieves data associated with a message in the mailbox. |
| CLOSE | Removes all messages with the Deleted flag set. |
| LOGOUT | Closes the connection with the IMAP server. |

### POP3 Commands

| Command | Description |
| --- |  --- |
| USER username | Identifies the user. |
| PASS password | Authentication of the user using its password. |
| STAT | Requests the number of saved emails from the server. |
| LIST | Requests from the server the number and size of all emails. |
| RETR id | Requests the server to deliver the requested email by ID. |
| DELE id | Requests the server to delete the requested email by ID. |
| CAPA | Requests the server to display the server capabilities. |
| RSET | Requests the server to reset the transmitted information. |
| QUIT | Closes the connection with the POP3 server. |
