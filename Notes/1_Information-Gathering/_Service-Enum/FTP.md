Footprining:

`sudo nmap -sV -p21 -sC -A 10.129.14.136`

**Download all available files:**

`
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
`

**Find NSE scripts:**

`
find / -type f -name ftp\* 2>/dev/null | grep scripts
`

### **FTP Command Line**

| Type | Command | What it Does |
| --- |  --- |  --- |
| Command Line | \-v | Suppresses verbose display of remote server responses. |
| Command Line | \-n | Suppresses auto login |
| Command Line | \-i | Turns off interactive prompting during multiple file transfers. |
| Command Line | \-d | Enables debugging, displaying all ftp commands passed between the client and server. |
| Command Line | --g | Disables filename globbing, which permits the use of wildcard chracters in local file and path names. |
| Command Line | \-s:filename | Specifies a text file containing ftp commands; the commands will automatically run after ftp starts. No spaces are allowed in this parameter. Use this switch instead of redirection (>). |
| Command Line | \-a | Use any local interface when binding data connection. |
| Command Line | \-w:windowsize | Overrides the default transfer buffer size of 4096. |
| Command Line | \-computer | Specifies the computer name or IP address of the remote computer to connect to. The computer, if specified, must be the last parameter on the line. |

### **FTP Command List**

| Type | Command | What it Does |
| --- |  --- |  --- |
| Command | ! | Runs the specified command on the local computer |
| Command | ? | Displays descriptions for ftp commands |
| Command | append | Appends a local file to a file on the remote computer |
| Command | ascii | Sets the file transfer type to ASCII, the default |
| Command | bell | Toggles a bell to ring after each file transfer command is completed (default = OFF) |
| Command | binary | Sets the file transfer type to binary |
| Command | bye | Ends the FTP session and exits ftp |
| Command | cd | Changes the working directory on the remote computer |
| Command | close | Ends the FTP session and returns to the command interpreter |
| Command | debug | Toggles debugging (default = OFF) |
| Command | delete | Deletes a single file on a remote computer |
| Command | dir | Displays a list of a remote directoryâ€™s files and subdirectories |
| Command | disconnect | Disconnects from the remote computer, retaining the ftp prompt |
| Command | get | Copies a single remote file to the local computer |
| Command | glob | Toggles filename globbing (wildcard characters) (default = ON) |
| Command | hash | Toggles hash sign (#) printing for each data block transferred (default = OFF) |
| Command | help | Displays descriptions for ftp commands |

| Type | Command | What it Does |
| --- |  --- |  --- |
| Command | lcd | Changes the working directory on the local computer |
| Command | literal | Sends arguments, verbatim, to the remote FTP server |
| Command | ls | Displays an abbreviated list of a remote directory's files and subdirectories |
| Command | mdelete | Deletes one or more files on a remote computer |
| Command | mdir | Displays a list of a remote directory's files and subdirectories |
| Command | mget | Copies one or more remote files to the local computer |
| Command | mkdir | Creates a remote directory |
| Command | mls | Displays an abbreviated list of a remote directory's files and subdirectories |
| Command | mput | Copies one or more local files to the remote computer |
| Command | open | Connects to the specified FTP server |
| Command | prompt | Toggles prompting (default = ON) |
| Command | put | Copies a single local file to the remote computer |
| Command | pwd | Displays the current directory on the remote computer (literally, "print working directory") |
| Command | quit | Ends the FTP session with the remote computer and exits ftp (same as "bye") |
| Command | quote | Sends arguments, verbatim, to the remote FTP server (same as "literal") |
| Command | recv | Copies a remote file to the local computer |
| Command | remotehelp | Displays help for remote commands |
| Command | rename | Renames remote files |
| Command | rmdir | Deletes a remote directory |
| Command | send | Copies a local file to the remote computer (same as "put") |
| Command | status | Displays the current status of FTP connections |
| Command | trace | Toggles packet tracing (default = OFF) |
| Command | type | Sets or displays the file transfer type (default = ASCII) |
| Command | user | Specifes a user to the remote computer |
| Command | verbose | Toggles verbose mode (default = ON) |