#!/usr/bin/python

# from string import printable

def decrypt(key, msg):
	key = list(key)
	msg = list(msg)
	for char_key in reversed(key):
		for i in reversed(range(len(msg))):
			if i == 0:
				tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
			else:
				tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
			while tmp < 0:
				tmp += 256
			msg[i] = chr(tmp)
	return ''.join(msg)

c = open('encryptorinator/ciphertext','r')
ciphertext = c.read()

# print(ciphertext)

f = open('/usr/share/wordlists/rockyou.txt','rb')
passwords = f.readlines()

# printableOrd = [ord(x) for x in printable]

wordsInMsg = ['pass', 'crypto', 'message', 'key', 'Key', 'the', 'The']

for p in passwords:
	passwd = p[:-1]
	# print(passwd)
	plaintext = decrypt(passwd,ciphertext)
	flag = 0
	for i in wordsInMsg:
		if i in plaintext:
			print(passwd)
			print(plaintext)
			flag = 1
			break
	if flag == 1:
		break
	# flag = 0
	# last = len(plaintext)
	# for i in range(last):
	# 	if ord(plaintext[i]) not in printableOrd:
	# 		break
	# 	if i==last-1:
	# 		flag = 1
	# if flag == 1:
	# 	print(passwd)
	# 	print(plaintext)
	# 	break
