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

