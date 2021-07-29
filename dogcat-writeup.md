
# dogcat room - CTF

Link to the room : https://tryhackme.com/room/dogcat

My IP address : 10.11.41.82

Target IP address : 10.10.220.208

My OS : Kali GNU/Linux 2021.2

## Enumeration

As always we should enumerate our target before trying to access any of the services. 
```
sudo nmap -sSVC -n -p- -T4 -A -O 10.10.220.208

PORT  STATE   SERVICE and VERSION
22    open    ssh OpenSSH 7.6p1 Ubuntu
80    open    Apache 2.4.38 Debian
```
We can see that it is clearly a Linux machine. Let's see the website and then decide what to do next. 

First thing we see on the website are two buttons and their task is to show you a random picture of cat or a dog. First thing that looks promising is that the URL is using 
`?view=` parameter. 

TBC
