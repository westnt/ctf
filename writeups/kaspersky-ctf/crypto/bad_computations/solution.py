from base64 import b64decode

msg = bytearray(b64decode("hnd/goJ/e4h1foWDhYOFiIZ+f3l1e4R5iI+Gin+FhA=="))
for i in range(len(msg)):
    msg[i] = msg[i] - 22
print(msg.decode("utf-8"))