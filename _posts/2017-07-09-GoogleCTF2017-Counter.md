---
layout: post
title:  "GoogleCTF 2017 - Counting"
date:   2017-07-09 22:06
categories: CTF
tags: [GoogleCTF2017]
categories: [Reversing]
author: jbz
---


> Counter
> This strange program was found, which apparently specialises in counting. In order to find the flag, you need to output find what the output of ./counter 9009131337 is.



With this witeup we won 100$ from Google :)


In this challenge, an executable is given (with some additional file), and it is required to provide the output of the executable when the input is "9009131337".

By trying to execute the program on small inputs the result is the following:


```
$ for i in `seq 0 30`; do ./counter $i ; done
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000000}
CTF{0000000000000008}
CTF{0000000000000036}
CTF{0000000000000023}
CTF{000000000000001d}
CTF{000000000000004e}
CTF{000000000000001c}
CTF{000000000000006b}
CTF{0000000000000031}
CTF{0000000000000017}
CTF{0000000000000065}
CTF{00000000000000bb}
CTF{0000000000000035}
CTF{00000000000000e7}
CTF{00000000000000c6}
CTF{000000000000000d}
CTF{00000000000000e5}
CTF{00000000000000d1}
CTF{0000000000000123}
CTF{000000000000011c}
CTF{000000000000013a}
```

By trying bigger inputs, we can see that the program becomes slower and slower: it seems to roughly double at each increment of the input...

```
$ for i in `seq 30 37`; do time ./counter $i ; done
CTF{000000000000013a}

real	0m1.059s
user	0m1.056s
sys	0m0.000s
CTF{0000000000000066}

real	0m1.704s
user	0m1.704s
sys	0m0.000s
CTF{0000000000000075}

real	0m2.736s
user	0m2.736s
sys	0m0.000s
CTF{0000000000000200}

real	0m4.383s
user	0m4.380s
sys	0m0.000s
CTF{0000000000000148}

real	0m7.137s
user	0m7.136s
sys	0m0.000s
CTF{000000000000009d}

real	0m11.430s
user	0m11.428s
sys	0m0.000s
CTF{0000000000000160}

real	0m19.832s
user	0m19.828s
sys	0m0.004s
CTF{0000000000000001}

real	0m30.787s
user	0m30.784s
sys	0m0.000s
```

Thus, compute the output of `9009131337` would require too much time.

Let's see what the program does, with IDA and hexrays.

```
signed __int64 __fastcall main(int a1, char **a2, char **a3)
{
  signed __int64 result; // rax@2
  int v4; // ebp@4
  _QWORD *v5; // rax@4
  __int64 v6; // rdx@4
  _QWORD *v7; // rbx@4

  if ( a1 == 2 )
  {
    v4 = strtol(a2[1], 0LL, 10);
    sub_400990();
    v5 = malloc(0xD0uLL);
    v6 = 0LL;
    v7 = v5;
    do
    {
      v5[v6] = 0LL;
      ++v6;
    }
    while ( v6 != 26 );
    *v5 = v4;
    sub_4008A0(v5, 0);
    __printf_chk(1LL, "CTF{%016llx}\n", *v7);
    free(v7);
    result = 0LL;
  }
  else
  {
    puts("Need one argument");
    result = 1LL;
  }
  return result;
}
```

The main function is simple: it parses the given parameter, it reads the additional file using `sub_400990()`, and then it calls `sub_4008A0(v5, 0)` to compute the flag.

Let's see what `sub_4008A0` does.

``` 
void __fastcall sub_4008A0(_QWORD *__attribute__((__org_arrdim(0,0))) a1, int a2)
{
  int v2; // edx@1
  _DWORD *v3; // rbx@3
  int v4; // eax@3
  char *v5; // rax@8
  __int64 v6; // rdx@8
  char *v7; // r12@8
  int v8; // eax@10
  unsigned __int64 v9; // rdx@11
  _QWORD *v10; // rax@14

  v2 = dword_602090;
  while ( a2 != v2 )
  {
    while ( 1 )
    {
      v3 = (_DWORD *)(qword_602098 + 16LL * a2);
      v4 = *v3;
      if ( *v3 )
        break;
      a2 = v3[2];
      ++a1[*((_BYTE *)v3 + 4)];
      if ( a2 == v2 )
        return;
    }
    if ( v4 == 1 )
    {
      v10 = &a1[*((_BYTE *)v3 + 4)];
      if ( *v10 )
      {
        a2 = v3[2];
        --*v10;
      }
      else
      {
        a2 = v3[3];
      }
    }
    else if ( v4 == 2 )
    {
      v5 = (char *)malloc(0xD0uLL);
      v6 = 0LL;
      v7 = v5;
      do
      {
        *(_QWORD *)&v5[v6 * 8] = a1[v6];
        ++v6;
      }
      while ( v6 != 26 );
      sub_4008A0(v5, v3[2]);
      v8 = v3[1];
      if ( v8 )
      {
        v9 = 0LL;
        do
        {
          a1[v9 / 8] = *(_QWORD *)&v7[v9];
          v9 += 8LL;
        }
        while ( v9 != 8LL * (unsigned int)(v8 - 1) + 8 );
      }
      free(v7);
      a2 = v3[3];
      v2 = dword_602090;
    }
  }
}
```

This is the decompiled code. After making it more readable we obtain the following:

```
struct line dump[] = {...}; //it roughly contains the additional file

struct line{
    unsigned char type;
    unsigned char pin;
    unsigned char p1;
    unsigned char p2;
};


void f(unsigned long *input, int i){
  struct line *lines = (struct line*)dump;

  while ( i != 0x77 ){
    
    for(;lines[i].type == 0;i = lines[i].p1){          
      if ( i == 0x77 )
        return;
      input[lines[i].pin]++;
    }
    
    if ( lines[i].type == 1 ){
      if ( input[lines[i].pin] ){
        input[lines[i].pin]--;
        i = lines[i].p1;
      }else{
        i = lines[i].p2;
      }
    }
    else if ( lines[i].type == 2 ){
      unsigned long *copy = (unsigned long *)malloc(0x0D0);
      memcpy(copy,input,0xd0);
      f(copy, lines[i].p1);
      memcpy(input,copy,lines[i].pin*8);
      free(copy);
      i = lines[i].p2;
    }
  }
}
```

Obtaining a working executable code was not so easy, because the pseudocode given by hexrays was partially incorrect.

This code is actually an interpreter for the code contained in the additional file. The additional file is composed by 119 lines, containing 4 numbers each.
By reading the interpreter code we can better understand how the language works.

The program starts at the first line and  terminates when the last line is reached. The memory is the input itself.

Each line is of the form:

```
OPCODE INPOS JUMP1 JUMP2
```

There are just three operations:

```
OPCODE 0: increment input at position INPOS and jump at instruction JUMP1
    
OPCODE 1: if input at position INPOS is different from 0, decrement it and jump at instruction JUMP1, else jump at instruction JUMP2

OPCODE 2: fork the execution and clone the memory, the child continues the execution at JUMP1, the parent waits the termination of the child, and then it copies the first INPOS words of the memory of the child to its memory.
```

An example is the following (the first 5 lines of the given code):

```
0x01, 0x00, 0x01, 0x02,
0x00, 0x01, 0x00, 0x00,
0x00, 0x02, 0x03, 0x00,
0x00, 0x02, 0x04, 0x00,
0x00, 0x02, 0x05, 0x00,
```

They can be translated to:

```
0: if( m[0]>0 ){ m[0]--; jump 1; }else{ jump 2; }
1: m[1]++; jump 0;
2: m[2]++; jump 3;
3: m[2]++; jump 4;
4: m[2]++; jump 5;
```
And they can be simplified to:

```
m[1] += m[0];
m[0] = 0;
m[2] += 3;
```

The first thing that we tried to do was to translate the program to something readable. The beginning for example translates to:

```
s[1] += s[0];
s[2] = 11;
s[0] = f108();
if( s[0] ){ s[0]--; return;}
s[2] = f20();
s[0] = f64();
return;
```
The problem was that the code is not so well structured. In some parts there were jumps to the beginning of the program, that makes the analysis hard. Thus, we changed approach: we tried to understand what the program does by inspecting the result of the forks (opcode 2).


The complete program is the following:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char dump2[] = {
0x01, 0x00, 0x01, 0x02,
0x00, 0x01, 0x00, 0x00,
0x00, 0x02, 0x03, 0x00,
0x00, 0x02, 0x04, 0x00,
0x00, 0x02, 0x05, 0x00,
0x00, 0x02, 0x06, 0x00,
0x00, 0x02, 0x07, 0x00,
0x00, 0x02, 0x08, 0x00,
0x00, 0x02, 0x09, 0x00,
0x00, 0x02, 0x0a, 0x00,
0x00, 0x02, 0x0b, 0x00,
0x00, 0x02, 0x0c, 0x00,
0x00, 0x02, 0x0d, 0x00,
0x02, 0x01, 0x6c, 0x0e,
0x01, 0x00, 0x77, 0x0f,
0x02, 0x01, 0x14, 0x10,
0x01, 0x02, 0x10, 0x11,
0x01, 0x00, 0x12, 0x13,
0x00, 0x02, 0x11, 0x00,
0x02, 0x01, 0x40, 0x77,
0x01, 0x02, 0x14, 0x15,
0x02, 0x01, 0x1d, 0x16,
0x01, 0x00, 0x17, 0x18,
0x00, 0x02, 0x16, 0x00,
0x01, 0x01, 0x19, 0x1a,
0x01, 0x19, 0x00, 0x15,
0x01, 0x00, 0x1a, 0x1b,
0x01, 0x02, 0x1c, 0x77,
0x00, 0x00, 0x1b, 0x00,
0x01, 0x02, 0x1d, 0x1e,
0x02, 0x01, 0x54, 0x1f,
0x01, 0x03, 0x1f, 0x20,
0x01, 0x00, 0x21, 0x22,
0x00, 0x03, 0x20, 0x00,
0x01, 0x03, 0x23, 0x2a,
0x01, 0x03, 0x24, 0x2a,
0x02, 0x01, 0x2d, 0x25,
0x00, 0x02, 0x26, 0x00,
0x01, 0x01, 0x26, 0x27,
0x01, 0x00, 0x28, 0x29,
0x00, 0x01, 0x27, 0x00,
0x01, 0x19, 0x00, 0x1e,
0x01, 0x00, 0x2a, 0x2b,
0x01, 0x02, 0x2c, 0x77,
0x00, 0x00, 0x2b, 0x00,
0x01, 0x02, 0x2d, 0x2e,
0x02, 0x01, 0x54, 0x2f,
0x01, 0x00, 0x30, 0x31,
0x00, 0x02, 0x2f, 0x00,
0x02, 0x02, 0x5c, 0x32,
0x01, 0x01, 0x33, 0x77,
0x01, 0x00, 0x33, 0x34,
0x01, 0x01, 0x34, 0x35,
0x01, 0x02, 0x36, 0x37,
0x00, 0x01, 0x35, 0x00,
0x02, 0x01, 0x54, 0x38,
0x01, 0x00, 0x39, 0x3a,
0x00, 0x02, 0x38, 0x00,
0x02, 0x01, 0x54, 0x3b,
0x01, 0x01, 0x3c, 0x3d,
0x00, 0x00, 0x3b, 0x00,
0x01, 0x02, 0x3e, 0x3f,
0x00, 0x00, 0x3d, 0x00,
0x00, 0x00, 0x77, 0x00,
0x02, 0x01, 0x54, 0x41,
0x01, 0x03, 0x41, 0x42,
0x01, 0x00, 0x43, 0x44,
0x00, 0x03, 0x42, 0x00,
0x01, 0x03, 0x45, 0x77,
0x00, 0x00, 0x46, 0x00,
0x01, 0x03, 0x47, 0x77,
0x01, 0x01, 0x48, 0x77,
0x02, 0x01, 0x40, 0x49,
0x01, 0x04, 0x49, 0x4a,
0x01, 0x00, 0x4b, 0x4c,
0x00, 0x04, 0x4a, 0x00,
0x01, 0x01, 0x4d, 0x77,
0x02, 0x01, 0x40, 0x4e,
0x01, 0x00, 0x4f, 0x50,
0x00, 0x04, 0x4e, 0x00,
0x01, 0x01, 0x50, 0x51,
0x01, 0x04, 0x52, 0x53,
0x00, 0x01, 0x51, 0x00,
0x02, 0x01, 0x63, 0x77,
0x01, 0x00, 0x54, 0x55,
0x01, 0x01, 0x56, 0x77,
0x00, 0x00, 0x55, 0x00,
0x01, 0x00, 0x57, 0x58,
0x01, 0x01, 0x59, 0x5a,
0x00, 0x00, 0x58, 0x00,
0x01, 0x02, 0x5b, 0x77,
0x00, 0x00, 0x5a, 0x00,
0x01, 0x00, 0x5c, 0x5d,
0x01, 0x01, 0x5d, 0x5e,
0x01, 0x02, 0x5f, 0x77,
0x01, 0x02, 0x60, 0x62,
0x00, 0x00, 0x61, 0x00,
0x01, 0x19, 0x00, 0x5e,
0x00, 0x01, 0x77, 0x00,
0x02, 0x01, 0x6c, 0x64,
0x01, 0x00, 0x65, 0x67,
0x01, 0x01, 0x66, 0x77,
0x00, 0x00, 0x65, 0x00,
0x02, 0x01, 0x71, 0x68,
0x01, 0x01, 0x68, 0x69,
0x01, 0x00, 0x6a, 0x6b,
0x00, 0x01, 0x69, 0x00,
0x01, 0x19, 0x00, 0x63,
0x01, 0x00, 0x6c, 0x6d,
0x01, 0x02, 0x6e, 0x77,
0x01, 0x01, 0x6f, 0x70,
0x01, 0x19, 0x00, 0x6c,
0x00, 0x00, 0x77, 0x00,
0x01, 0x02, 0x72, 0x74,
0x01, 0x01, 0x73, 0x77,
0x01, 0x19, 0x00, 0x71,
0x01, 0x00, 0x74, 0x75,
0x01, 0x01, 0x76, 0x77,
0x00, 0x00, 0x75, 0x00,
0x00, 0x00, 0x41, 0x00,
0x00, 0x00, 0x00, 0x00,
};


struct line{
    unsigned char type;
    unsigned char pin;
    unsigned char p1;
    unsigned char p2;
};

void f(unsigned long *input, int i){
  struct line *lines = (struct line*)dump2;

  while ( i != 0x77 ){
    
    for(;lines[i].type == 0;i = lines[i].p1){          
      if ( i == 0x77 )
        return;
      input[lines[i].pin]++;
    }
    
    if ( lines[i].type == 1 ){
      if ( input[lines[i].pin] ){
        input[lines[i].pin]--;
        i = lines[i].p1;
      }else{
        i = lines[i].p2;
      }
    }
    else if ( lines[i].type == 2 ){
      unsigned long *copy = (unsigned long *)malloc(0x0D0);
      memcpy(copy,input,0xd0);
      f(copy, lines[i].p1);
      if( lines[i].p1==20 || lines[i].p1==29 || lines[i].p1 == 45||lines[i].p1 == 64){
          printf("%d) %ld %ld %ld %ld %ld %ld -> %ld\n",lines[i].p1,input[0],input[1],input[2],input[3],input[4],input[25],copy[0]);
      }
      memcpy(input,copy,lines[i].pin*8);
      free(copy);
      i = lines[i].p2;
    }
  }
}

int main(int argc, char *argv[]){
    long v4 = atol(argv[1]);
    unsigned long v5[26] = {0};
    v5[0] = v4;
    f(v5,0);
    printf("%ld CTF{%016lx}\n",calls,v5[0]);
}

```
In particular, this part writes the memory after some interesting function calls:

```
      f(copy, lines[i].p1);
      if( lines[i].p1==20 || lines[i].p1==29 || lines[i].p1 == 45||lines[i].p1 == 64){
          printf("%d) %ld %ld %ld %ld %ld %ld -> %ld\n",lines[i].p1,input[0],input[1],input[2],input[3],input[4],input[25],copy[0]);
      }
```

Let's see the calls to function 64:

```
$ ./source 11 | grep "64)"
64) 1 1 81 0 0 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 0 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 0 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 0 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 0 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 1 6 81 5 0 0 -> 8
64) 1 1 81 0 8 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 8 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 8 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 8 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 0 5 81 5 8 0 -> 5
64) 1 7 81 6 0 0 -> 13
64) 1 1 81 0 13 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 13 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 13 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 13 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 13 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 0 6 81 6 13 0 -> 8
64) 1 8 81 7 0 0 -> 21
64) 1 1 81 0 21 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 21 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 21 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 21 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 21 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 1 6 81 5 21 0 -> 8
64) 1 1 81 0 8 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 8 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 8 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 8 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 0 5 81 5 8 0 -> 5
64) 0 7 81 7 21 0 -> 13
64) 1 9 81 8 0 0 -> 34
64) 1 1 81 0 34 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 34 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 34 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 34 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 34 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 1 6 81 5 34 0 -> 8
64) 1 1 81 0 8 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 8 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 8 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 8 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 0 5 81 5 8 0 -> 5
64) 1 7 81 6 34 0 -> 13
64) 1 1 81 0 13 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 13 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 13 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 13 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 13 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 0 6 81 6 13 0 -> 8
64) 0 8 81 8 34 0 -> 21
64) 1 10 81 9 0 0 -> 55
64) 1 1 81 0 55 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 55 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 55 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 55 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 55 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 1 6 81 5 55 0 -> 8
64) 1 1 81 0 8 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 8 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 8 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 8 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 0 5 81 5 8 0 -> 5
64) 1 7 81 6 55 0 -> 13
64) 1 1 81 0 13 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 13 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 13 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 13 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 13 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 0 6 81 6 13 0 -> 8
64) 1 8 81 7 55 0 -> 21
64) 1 1 81 0 21 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 21 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 21 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 21 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 1 5 81 4 21 0 -> 5
64) 1 1 81 0 5 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 5 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 5 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 0 4 81 4 5 0 -> 3
64) 1 6 81 5 21 0 -> 8
64) 1 1 81 0 8 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 8 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 1 3 81 2 8 0 -> 2
64) 1 1 81 0 2 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 0 2 81 2 2 0 -> 1
64) 1 4 81 3 8 0 -> 3
64) 1 1 81 0 3 0 -> 1
64) 0 0 81 0 1 0 -> 0
64) 1 2 81 1 3 0 -> 1
64) 0 1 81 1 1 0 -> 1
64) 0 3 81 3 3 0 -> 2
64) 0 5 81 5 8 0 -> 5
64) 0 7 81 7 21 0 -> 13
64) 0 9 81 9 55 0 -> 34
64) 0 11 81 0 0 0 -> 8
```
The list is very long, but there are many repeated calls, let's try to filter them.

```
$ ./source 11 | grep "64)" | cut -d ' ' -f 3,4,9 | sort -u -n
0 81 0
1 81 1
2 81 1
3 81 2
4 81 3
5 81 5
6 81 8
7 81 13
8 81 21
9 81 34
10 81 55
11 81 8
```
0 1 1 2 3 5 8 13 21 34 55 is the Fibonacci sequence, but why there is 8 then? The next number would be 34+55=89. Also, there is an 81 as parameter that we don't know where it comes from. Notice that 11 is the input parameter, and 8 is actually the result: `CTF{0000000000000008}`.

We can notice that 8 is exacty 89 - 81. After some trials we can notice that, given some input x, the program computes some number c and then it computes fib(x) mod c.

```
$ echo "x  c  result"; for i in `seq 11 25`; do ./source $i | grep "64)" | cut -d ' ' -f 3,4,9 | sort -n | uniq | tail -n 1 ; done
x  c  result
11 81 8
12 90 54
13 99 35
14 116 29
15 133 78
16 137 28
17 149 107
18 169 49
19 189 23
20 196 101
21 203 187
22 218 53
23 233 231
24 243 198
25 266 13
```

What remains to do is to see how c (81,90,99,116,133,137,149, ...) is computed. First we can see that c is produced by the function 20:

$ ./source 11 | grep "20)" 
20) 0 11 11 0 0 0 -> 81

Let us look at the code starting at line 20:

```
0x01, 0x02, 0x14, 0x15,
0x02, 0x01, 0x1d, 0x16,
0x01, 0x00, 0x17, 0x18,
0x00, 0x02, 0x16, 0x00,
...
```
This can be translated to:

```
s[2] = 0;
s[2] += f29();
s[0]=0;
...
```
So, let's see the calls to line 29:

```
$ ./source 11 | grep "29)" 
29) 0 11 0 0 0 0 -> 14
29) 0 10 14 0 0 0 -> 6
29) 0 9 20 0 0 0 -> 19
29) 0 8 39 0 0 0 -> 3
29) 0 7 42 0 0 0 -> 16
29) 0 6 58 0 0 0 -> 8
29) 0 5 66 0 0 0 -> 5
29) 0 4 71 0 0 0 -> 2
29) 0 3 73 0 0 0 -> 7
29) 0 2 80 0 0 0 -> 1
29) 0 1 81 0 0 0 -> 0
29) 0 0 81 0 0 0 -> 0
```

These are the results: 14 6 19 3 16 8 5 2 7 1 0 0. They sum up to 81! By doing some trials we can notice that this is always the case, c is the sum of f29(i) for i from 0 to x. Now, by analyzing the code starting at line 29, we can notice that it calls the code at line 45.

By just counting the number of calls, we can understand something:

```
$ ./source 11 | grep "45)"  | wc -l
81
```

The total number of calls is equal to the final result!

Let's see better what's happening:

```
$ ./source 11 | grep "45)\|29)"  
45) 0 11 0 9 0 0 -> 34
45) 0 34 1 32 0 0 -> 17
45) 0 17 2 15 0 0 -> 52
45) 0 52 3 50 0 0 -> 26
45) 0 26 4 24 0 0 -> 13
45) 0 13 5 11 0 0 -> 40
45) 0 40 6 38 0 0 -> 20
45) 0 20 7 18 0 0 -> 10
45) 0 10 8 8 0 0 -> 5
45) 0 5 9 3 0 0 -> 16
45) 0 16 10 14 0 0 -> 8
45) 0 8 11 6 0 0 -> 4
45) 0 4 12 2 0 0 -> 2
45) 0 2 13 0 0 0 -> 1
29) 0 11 0 0 0 0 -> 14
...
```

The calls are actually printed when they end, so the right order is the following:

```
f29(11) -> f45(11) -> f45(34) -> f45(17) -> ... -> f45(2) -> f29() = 14
```
Notice that 14 is just the length of the chain 11,34,17,52,26,13,40,20,10,5,16,8,4,2. But, what is this chain? This is Collatz!

Collatz says the following: take a number, if it is even divide it by two, if it is odd multiply it by three and add one. By repeating this process you'll arrive to 1. It is an open problem to prove that the Collatz conjecture is true, but it actually holds for every big number that you can test with a computer. f29 essentially counts the number of steps required to reach 1, starting from the given number.


Summarizing, the program does the following:

```
read some input x
compute the length of the collatz sequence for each i from 1 to x
sum all the computed lengths, call the sum c
compute fibonacci(x) modulo c

```

Let's implement this. Notice that we can not just compute fib(n) and then compute the modulo, because fib(n) would not fit in an integer, so we compute the modulo while computing fib.

```
#include <stdint.h>

uint64_t collatz(uint64_t n){
  uint64_t count = 0;
  while(n!=1){
      count++;
      if(n%2==0)n/=2;
      else n=n*3+1;
  }
  return count;
}

uint64_t fib(uint64_t n, uint64_t mod){
  uint64_t s1 = 0, s2 = 1,t;
  for(uint64_t i=0;i<n;i++){
      t = s1+s2;
      s1 = s2;
      s2 = t % mod;
  }
  return s1;
}

int main(int argc, char *argv[]){
    uint64_t n;
    //yes, argc should be checked
    sscanf(argv[1],"%ld",&n);
    uint64_t sum = 0;
    for(uint64_t i=1;i<=n;i++){
        sum += collatz(i);
    }
    uint64_t f = fib(n,sum);
    printf("CTF{%016lx}\n",f);
}

```

By trying this program you can see that it generates the same output of the original program. The problem is that it is too slow to compute the result given 9009131337 as input. A way to make it faster is to reuse the results of the previous collatz calls:

```
#define SAVE 1000000
uint64_t saved[SAVE];

uint64_t collatz(uint64_t n){
  uint64_t orig = n;
  uint64_t count = 0;
  while(n!=1){
      if( n < SAVE && saved[n] ){
          uint64_t res = saved[n]+count;
          if( orig < SAVE )saved[orig] = res;
          return res;
      }
      count++;
      if(n%2==0)n/=2;
      else n=n*3+1;
  }
  if( orig < SAVE )saved[orig] = count;
  return count;
}
```

Let's run it!

```
$ ./program 9009131337

```
And, after 10-15 minutes...

```
CTF{000001bae15b6382}
```

