goodMagic = '89504e470d0a1a0a' #magic number of png
with open("secret_encrypted.png") as f:
	data = f.read()

#find number file is xored with
for num in range(0,256):
	magic = ''
	for d in data[0:8]:
		magic += chr(ord(d)^num)
	if(magic.encode('hex') == goodMagic):
		print("number: " + str(num))
		break

#xor file with found number
decrypted = ''.join(chr( ord(d)^num ) for d in data)

with open('out.png','w') as of:
	of.write( decrypted )