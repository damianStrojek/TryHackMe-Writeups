
# tomghost room - CTF

Link to the room : https://tryhackme.com/room/tomghost

My IP address : 10.11.41.82

Target IP address : 10.10.206.57

My OS : Kali GNU/Linux 2021.2

## Enumeration

As always we should enumerate our target before trying to access any of the services. 
```
sudo nmap -sSVC -p- -n -O -T4 -A 10.10.206.57
PORT    STATE   SERVICE and VERSIOM
22      open    ssh OpenSSH 7.2p2 Ubuntu
53      open    tcpwrapped (probably nothing interesting)
8009    open    ajp13 Apache Jserv v1.3
8080    open    http Apache Tomcat 9.0.30
```

## Checking services and getting user access

First of all I tried to enumerate the webpage http://10.10.206.57:8080/ and I tried all of the default directories like /manager or /conf/tomcat-users.xml but nothing works so I 
moved to the other port. The SSH banner was empty but the Apache Jserv service was looking promising so I searched if there is any vulnerability that we could exploit. 
There was this python script that gives us File Read/Inclusion https://www.exploit-db.com/exploits/48143. 
```
./CVE-2020-1938.py 10.10.206.57
```
I ran it just to see if it works and to my surprise, without any additional configuration, I was able to retrieve .xml file with username (skyfuck) and password in it.
First flag user.txt was inside of /home/merlin/user.txt. 

## Escalating my privileges

### Horizontal escalating
    I had access to the machine so I tried to find any misconfiguration that would lead me to escalating my privileges to root. It's normal process (there is a cheatsheet on my 
    LinkedIn) and it includes checking all interesting files, directories, crontabs, IPTables and running LinPEAS.sh .

    In home directory of skyfuck I found out two files credential.pgp and tryhackme.asc. They were looking promising so I copied them into my attacker machine and tried to decode.
    ```
    scp skyfuck@10.10.206.57:/home/skyfuck/credential.pgp ./credential.pgp
    scp skyfuck@10.10.206.57:/home/skyfuck/tryhackme.asc ./tryhackme.asc
    ```
    Then I had to use one of the john's tool called gpg2john to crack the password that was protecting this file.
    ```
    gpg2john tryhackme.asc > tocrack
    john --wordlist=/usr/share/wordlists/rockyou.txt tocrack
    ```
    And by doing this I was able to crack password protecting this .gpg file and obtain credentials to log in as merlin onto our target machine. It's called horizontal privilege 
    escalation because we are not getting root privileges but now we have access to the second user on this machine and we can look for other vulnerabilities like SUID files 
    etc.
 ### Vertical escalating
    I was doing a lot of researching before trying the `sudo -l` command and that was my mistake. As soon as you try it you are able to see that this user can run zip with sudo 
    without the password. After that vertical escalating was really easy to accomplish. All you have to do is go to https://gtfobins.github.io/ and search for "zip". Last section 
    is for "Limited SUID" which is exactly what we need.
    ```
    mktemp -u
    sudo zip $(mktemp -u) /etc/hosts -T -TT 'sh #'
    ```
    The $(mktemp -u) is value of the temporary file. You can just copy it from the output of first command.
    
    Right after this you have root access and you can grab root.txt flag inside /root/ directory. Thank you for reading.



