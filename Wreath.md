# Wreath Room
My IP address : 10.10.156.24
My OS : Kali GNU/Linux 2021.2
This whole file is like a private note that will help me in the future but feel free to learn with me.

## Gathered information about the network :
- There are three machines on the network, where at least one has public facing webserver turned on
- There is internal git server that is self-hosted somewhere in the network
- One of the machines has antivirus installes so we can assume this is Windows machine and we cannot acces it directly from the webserver

## Enumeration
First off we need to enumerate our target. There is only one IP provided for us (10.200.159.200) so we will start with this one.
```
sudo nmap -sSVC -p- 10.200.159.200

PORT    STATE   SERVICE and VERSION
22      open    ssh OpenSSH 8.0
80      open    http Apache 2.4.37 (centos)
443     open    ssl/http Apache 2.4.37 (centos)
9090    open    zeus-admin (probably not relevant)
10000   open    MiniServ 1.89 (webmin)
```
After that I usually scan the target again, with other parameters, to make sure that we didn't miss anything. For example :
```
sudo nmap -sV -p- -A -O 10.200.159.200 
```
We can't see any new services/ports but because of the -O parameter we get the 89% agressive OS guess that this machine is running Linux (we were able to retrieve this information
before from 80/443 port scan.
## Checking services
  ### HTTP
  After the enumeration we can check all of the available services. For example you can connect to the ssh `ssh root@10.200.159.200` and check if there is any banner shown.
  Next up we need to check the webpage. When we try to enter we are redirected to https://thomaswreath.thm/. As we can see there is no DNS that will resolve this for us. 
  To get access we need to edit our /etc/hosts file.
  ```
  10.200.159.200    thomaswreath.thm
  ```
  With that out of our way we are able to get access to this webpage where we are welcomed with resume website of Thomas Wreath.
  In real life penetration test you should "footprint" this person. That's what we will try to do but on a much lower scale. First up I will find everything that can be useful
  in the future that is on this website.
  1. Thomas' mobile phone number and phone number : +447821548812 and 01347 822945
  2. Thomas' address : 21 Highland Court in Yorkshire, England
  3. His mail : me@thomaswreath.thm

  Next up we can see that the page was done with the help of Online CV design by ThemeHippo. Sometimes it is useful information, for example when the site is made with wordpress.
  Normally we should enumerate this page with dirb/dirbuster/gobuster and maybe directory-list-2.3-medium.txt but for now we'll move on to the next service.
  ### Webmin HTTP
  We can start with checking if this version of the webmin is vulnerable to any exploit. Quick search with google gives us information that we wanted.
  On https://github.com/MuirlandOracle/ you are able to find the CVE-2019-15107 exploit that gives us unauthorized Remote Command Execution on this machine. 
  You can simply clone it onto your machine and install all of the requirements to run this exploit.
  ```
  git clone https://github.com/MuirlandOracle/CVE-2019-15107
  pip3 install -r requirements.txt
  chmod +x CVE-2019-15107.py
  ```
  After all of the requirements are satisfied we are able to obtain a reverse shell to the target machine.
  ```
  ./CVE-2019-15107.py 10.200.159.200
  ```
  Luckily this webserver is running as a root so we don't have to escalate our privileges! But still we have to stabilise our shell.
  There is this functionality to obtain a stable reverse shell with this CVE but I wasn't able to do it (couldn't type in my IP address and port where my netcat was listening)
  so I read the /.ssh/id_rsa file of root and connected through ssh to stabilise my shell.
  ```
  cat /root/.ssh/id_rsa
  nano id_rsa
  chmod 600 id_rsa
  ssh -i id_rsa root@10.200.159.200
  ```
 ## Pivoting
  Right now we are inside of first machine but we need to keep going and keep enumerating so we can start pivoting. Pivoting is the art of using access obtained over one machine
  to exploit another machine deeper in the network. It is one of the most essential aspects of network penetration testing. There are two main methods of pivoting :
  - Tunnelling/Proxying - Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially
  also be tunnelled inside another protocol (e.g. SSH tunnelling) which can be useful for evading a basic IDS or firewall.
  - Port Forwarding - Creating a connection between a local port and a single port on a target via compromised host.
  
  Which style of pivoting is more suitable will depend entirely on the layout of the network, so we'll have to start with further enumeration before we decide how to proceed.
  ### Enumerating before pivoting
  Information is power - our first step when attempting to pivot through a network is to get an idea of what's around us. Ideally we want to take advantage of pre-installed
  tools on the system to enumerate a network through a compromised host. This is called Living off the Land (LotL) - a good way to minimise risk.
  ```
  ifconfig
  arp -a
  cat /etc/hosts
  cat /etc/resolv.conf
  ```
  
  
  
  
  
  
  
