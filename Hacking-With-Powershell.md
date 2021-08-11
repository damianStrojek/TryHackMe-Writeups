
# Hacking with Powershell

Link to the room : https://tryhackme.com/room/powershell

My IP address : 10.8.202.86

Target IP address : 10.10.14.179

My OS : Kali GNU/Linux 2021.2

## Introduction to Powershell

Powershell is the Windows Scripting Language and shell environment that is built using the .NET framework. This also allows Powershell to execute .NET functions directly from its 
shell. Most Powershell commands, called _cmdlets_, are written in .NET. Unlike other scripting languages and shell environments, the output of these _cmdlets_ are objects - making 
Powershell somewhat object oriented. The normal format of a _cmdlet_ is represented using Verb-Noun. Common verbs to use include :

- Get
- Start
- Stop
- Read
- Write
- New
- Out


The `Get-Command` and `Get-Help` command are your best friends. `Get-Help` displays information about a _cmdlet_. You can also understand how exactly to use the command by 
passing in the `-examples` flag.
```
Get-Help <COMMAND NAME>
Get-Help Get-Command -examples
```
`Get-Command` on the other hand gets all the _cmdlets_ installed on the current Computer. The great thing about this _cmdlet_ is that it allows for pattern matching, for example :
```
Get-Command New-*
Get-Command Verb-*
Get-Command Start-*
```


If we want to **manipulate** the output we need to know how to pass output to other _cmdlets_ and how to use specific object _cmdlets_ to extract information. The Pipeline `|` is used 
to pass output from one _cmdlet_ to another, the same way it is done on Linux. A major difference compared to other shells is that instead of passing text or string to the command 
after the pipe, powershell passes an object to the next _cmdlet_.
```
Get-Command | Get-Member -MemberType Method
Verb-Noun | Get-Member
```


One way of manipulating objects is pulling out the properties from the output of a _cmdlet_ and creating a new object. This is done using the `Select-Object` _cmdlet_.
```
Get-ChildItem | Select-Object -Property Mode, Name
```
This creates new object with only two sections of the `Get-ChildItem` _cmdlet_. You can also use the following flags to select particular information :
- first - gets the first x object
- last - gest the last x object
- unique - shows the unique objects
- skip - skips x objects


When retrieving output objects, you may want to select objects that match a very specific value (on Linux you can use `grep` for this). You can do this using the `Where-Object` 
to filter based on the value of properties. The general format of the using this _cmdlet_ is :
```
Verb-Noun | Where-Object -Property <PROPERTY NAME> -<OPERATOR> <VALUE>
```
where operators are e.g. :
- Contains - if any item in the property value is an exact match
- EQ - if the property value is the same
- GT - if the property value is greater

Here is the example of checking stopped processes :
```
Get-Service | Where-Object -Property Status -eq Stopped
```


When a _cmdlet_ outputs a lot of information you may need to **sort it** to extract the information more effectively. You do this by pipe lining the output of a _cmdlet_ to the 
`Sort-Object` _cmdlet_.
```
Get-ChildItem | Sort-Object
```

### Questions 1
  1. What is the location of the file "interesting-file.txt"?
     ```
     Get-ChildItem -Path C:\ -Include interesting-file.txt.txt -File -Recurse

     Directory: C:\ProgramFiles\interesting-file.txt.txt
     ```
  2. Specify the content of this file
     ```
     Get-Content -Path "C:\Program Files\interesting-file.txt.txt"

     notsointerestingcontent
     ```
  3. How many _cmdlets_ are installed on the system (only cmdlets, not functions and aliases)?
     ```
     Get-Command | Where-Object -Property CommandType -eq Cmdlet | measure

     6638
     ```
  4. Get the MD5 hash of interesting-file.txt
     ```
     Get-FileHash -Algorithm MD5 -Path "C:\Program Files\interesting-file.txt.txt"

     49A586A2A9456226F8A1B4CEC6FAB329
     ```
  5. What is the command to get the current working directory?
     ```
     Get-Location
     ```
  6. Does the path "C:\Users\Administrators\Documents\Passwords" Exist (Y/N)?
     ```
     cd "C:\Users\Administrators\Documents\Passwords"

     Cannot find path "C:\Users\Administrators\Documents\Passwords" because it does not exist.
     ```
  7. What command would you use to make a request to a web server?
     ```
     Invoke-WebRequest
     ```
  8. Base64 decode the file b64.txt on Windows.
     I used base64 decode one-liner for powershell 
     ```
     [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<CONTENT OF THE FILE"))

     this is the flag - ihopeyoudidthisonwindows
     the rest is garbage
     [...]
     ```

## Enumeration with Powershell

### Questions 2
  1. How many users are there on the machine?
     ```
     Get-LocalUser

     5
     ```
  2. Which local user does this SID(<SID>) belong to?
     ```
     Get-LocalUser -SID <SID>

     Guest
     ```
  3. How many users have their password required values est to False?
     ```
     Get-LocalUser | Get-Member
     Get-LocalUser | Where-Object -Property PasswordRequired -eq false | measure
  
     4
     ```
  4. How many local groups exist?
     ```
     Get-LocalGroup | measure

     24
     ```
  5. What command did you use to get the IP address info?
     ```
     Get-NetIPAddress
     ```
  6. How many ports are listed as listening?
     ```
     Get-NetTcpConnection | measure

     20
     ```
  7. What is the remote address of the local port listening on port 445?
     ```
     Get-NetTcpConnection | Where-Object -Property LocalPort -eq 445

     ::
     ```
  8. How many patches have been applied?
     ```
     Get-Hotfix | measure

     20
     ```
  9. When was the patch with ID KB4023834 installed?
     ```
     Get-Hotfix | Where-Object -Property HotfixID -eq KB4023834

     6/15/2017 12:00:00 AM
     ```
 10. Find the contents of a backup file.
     ```
     Get-ChildItem -Path C:\ -Include *.bak* -File -Recurse
     Get-Content "C:\Program Files (x86)\Internet Explorer\passwords.bak.txt"

     backpassflag
     ```
 11. Search for all files containing API_KEY
     ```
     Get-ChildItem -Path C:\ -Recurse | Select-String -pattern API_KEY

     fakekey123
     ```
 12. What command do you do to list all the running processes?
     ```
     Get-Process
     ```
 13. What is the path of the scheduled task called new-sched-task?
     ```
     Get-ScheduledTask | Where-Object -Property TaskName -eq new-sched-task

     /
     ```
 14. Who is the owner of the C:\?
     ```
     Get-acl C:\

     NT SERVICE\TrustedInstaller
     ```

## Basic Scripting Challenge
  
     In the next task we are supposed to write our own script and run it to do more complex and powerful actions. The emails folder on the Desktop contains copes of the emails 
     John, Martha and Mary have been sending to each other. We need to answer following questions with regards to these emails. To write those scripts I am using Windows 
     Powershell ISE.
  1. What file contains the password?
  2. What is the password?
  3. What files contains an HTTPS link?
     ```
     $path = "C:\Users\Administrator\Desktop\emails\*"
     $string1 = "password"
     $string2 = "https"
     $script1 = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $string1
     $script2 = Get-ChildItem -Path $path -Recurse | Select-String -Pattern $string2
     echo $script1
     echo $script2
      
     doc3m.txt
     password : johnisalegend99
     doc2mary.txt
     ```
## Intermediate Scripting
  
     Now we need to write a script that will carry on a simple port scan using Powershell. I used Test-NetConnection and couldn't get the answer right because the output I was 
     given tells that there is only 1 port open. I don't really know why but this is the script with the correct answer :
     
  1. How many open ports did you find between 130 and 140?
     ```
     for($p=130; $p -le 140; $p++){
         Test-NetConnection localhost -Port $p
     }
      
     11
     ```
