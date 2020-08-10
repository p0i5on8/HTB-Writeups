#!/usr/bin/env python3

from string import ascii_letters

def getKey(cipherText, plainText):
	key = []
	for i in range(len(cipherText)):
		if cipherText[i] in ascii_letters:
			x = (ord(cipherText[i]) - ord(plainText[i]) + 26) % 26
			x += ord('a')
			key.append(chr(x))
	return "".join(key)

pt = "Orestis - Hacking for fun and profit"
ct1 = "Pieagnm - Jkoijeg nbw zwx mle grwsnn"
ct2 = "Wejmvse - Fbtkqal zqb rso rnl cwihsf"
ct3 = "Qbqquzs - Pnhekxs dpi fca fhf zdmgzt"

print(getKey(ct1,pt))
print(getKey(ct2,pt))
print(getKey(ct3,pt))
