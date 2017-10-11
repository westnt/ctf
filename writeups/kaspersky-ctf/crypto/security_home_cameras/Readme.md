We are provided with a encrypted png file "secret_encrypted.png".

opening this file in a hexeditor, I noticed bytes 8 to 10 where FF FF FF.
I suspected the unencrypted bytes would be 00 00 00 so they where probably xored with FF FF FF to result in FF FF FF.
If this is the case, the encryption is most likley a repeated xor key or the file is xored with a single number.

An aditional note: Since we know the format of a png file, the first 8 bytes (file signature) should be 89 50 4E 47 0D 0A 1A 0A.

Testing the theory that the file is xored with a single number, if we xor that number with the first 8 bytes of the encrypted
message, it should result in the file signature of a PNG.

```py
with open("secret_encrypted.png") as f:
	data = f.read()

#find number file is xored with
goodSignature = '89504e470d0a1a0a' #Signature of png
for num in range(0,256):
	signature = ''.join(chr(ord(d)^num) for d in data[0:8])
	if(signature.encode('hex') == goodSignature):
		print("number: " + str(num))
		break
```
Running the code tells us the file is xored with 255.

Now all we have to do is xor the file with 255 to get our decrypted png:
```py
#xor file with found number
decrypted = ''.join(chr( ord(d)^num ) for d in data)

with open('out.png','w') as of:
	of.write( decrypted )
```
<img src="out.png"/>
And thats it!
