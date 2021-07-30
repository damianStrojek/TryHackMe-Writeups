
# brainstorm room CTF

Link to the room : https://tryhackme.com/room/brainstorm

My IP address : 10.8.202.86

Target IP address : 10.10.156.134

My OS : Kali GNU/Linux 2021.2

## Enumeration

First off we need to enumerate our target. We know that the target doesn't respond to the ICMP echo requests so we need to use `-Pn` switch.
```
sudo nmap -Pn -p- 10.10.156.134

PORT  STATE   SERVICE and VERSION
21    open    ftp Microsoft ftpd
3389  open    ms-wbt-server
9999  open    abyss? Brainstorm

OS Scan : Microsoft Windows Server 2008 90%
```
Nmap is clearly telling us that there are 3 open ports on this host but the correct answer for the question is 6 open ports. I don't know why is it like this, probably it is 
author's mistake. Let's move on with our enumeration, next up we should enumerate ftp service and that 9999 port.

If we go into FTP `ftp 10.10.156.134` with credentials anonymous:anonymous we are able to see one directory with two files in it. One of them is executable and the other is 
a .dll file. We cannot go into webpage of port 9999 so we can try to connect with netcat.
```
nc -v 10.10.156.134 9999
```
We succeed! Now we are asked for username (max 20 characters). We are suspecting that this port is the attack vector for the buffer overflow. I tried 
