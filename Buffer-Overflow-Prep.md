
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

## OVERFLOW 1

