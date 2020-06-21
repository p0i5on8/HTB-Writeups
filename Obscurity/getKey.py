#!/usr/bin/python3

with open('robert_Encryption/check.txt', 'r', encoding='UTF-8') as f:
	check = f.read()

with open('robert_Encryption/out.txt', 'r', encoding='UTF-8') as f:
	out = f.read()

key = []
for i in range(len(check)):
	if ord(check[i]) > ord(out[i]):
		key += chr(ord(out[i]) - ord(check[i]) + 255)
	else:
		key += chr(ord(out[i]) - ord(check[i]))

print(''.join(key))

# output -->  alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal
# ==> key --> alexandrovich
