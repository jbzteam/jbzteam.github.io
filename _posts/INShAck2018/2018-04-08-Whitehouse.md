---
layout: post
title:  "INS'hAck CTF 2018 - Whitehouse"
date:   2018-04-08 23:00
categories: [INShAck2018]
tags: [Reverse, Crypto]
author: jbz
---

### Part 1
>We got access to the White House's registration page which allows to recover nuclear bomb codes.
>Will you be able to recover the nuclear codes for `Bill Clinton`?
>Please note that it's easy to get a nuclear code that looks like a flag for any username, but only `Bill Clinton`'s code will be valid (and you guessed it, the system won't let you get that one too easily).
>The White House's server is available at `nc whitehouse.ctf.insecurity-insa.fr 18470` 

By starting the binary we can notice that it does not allow us to register Bill Clinton:
```
$ ./white-house-insecurity masterkey 12345678901234567890123456789012
                    _ _.-'`-._ _
                   ;.'________'.;
        _________n.[____________].n_________
       |''_''_''_''||==||==||==||''_''_''_''|
       |'''''''''''||..||..||..||'''''''''''|
       |LI LI LI LI||LI||LI||LI||LI LI LI LI|
       |.. .. .. ..||..||..||..||.. .. .. ..|
       |LI LI LI LI||LI||LI||LI||LI LI LI LI|
    ,,;;,;;;,;;;,;;;,;;;,;;;,;;;,;;,;;;,;;;,;;,,
   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        WHITE HOUSE AUTHENTICATION SERVICE

What do you want to do ?
1. Register a new president
2. Generate nuclear bomb codes
3. Exit
Your choice : 1
Please enter your name : Bill Clinton
Error : President Bill Clinton is already registered.
```

By editing the binary and replacing "`Bill Clinton`" with anything else, we can solve the challenge.
```
$ ./whitehouse_edited masterkey 12345678901234567890123456789012
                    _ _.-'`-._ _
                   ;.'________'.;
        _________n.[____________].n_________
       |''_''_''_''||==||==||==||''_''_''_''|
       |'''''''''''||..||..||..||'''''''''''|
       |LI LI LI LI||LI||LI||LI||LI LI LI LI|
       |.. .. .. ..||..||..||..||.. .. .. ..|
       |LI LI LI LI||LI||LI||LI||LI LI LI LI|
    ,,;;,;;;,;;;,;;;,;;;,;;;,;;;,;;,;;;,;;;,;;,,
   ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        WHITE HOUSE AUTHENTICATION SERVICE

What do you want to do ?
1. Register a new president
2. Generate nuclear bomb codes
3. Exit
Your choice : 1
Please enter your name : Bill Clinton
Now raise your right hand and repeat after me :
I, Bill Clinton, do solemnly swear
yeah sure whatever
Welcome aboard, President Bill Clinton !
Your nuclear codes are INSA{8c0165004d4ab5d6}
In case you ever forget your nuclear codes, here is your token to generate them again :
106d1af3c1849dca5334a971861facbd
```

###Part 2
>The two parts of this challenge are independent, but we recommend doing Part 1 first, which will help you a lot to understand how the White House server works.
>We have one more mission for you : retrieve the nuclear master key. We heard only administrator is allowed to see them, but there must be a way...
>The server is the same as part 1.
>There is also a bonus part to this challenge : If you manage to leak the encryption key by any means WITHOUT BREAKING THE CHALL, please report it to an admin and we might award bug bounty points.
>I have no idea whether it's possible (spoiler alert : 600 lines of C written at 2am while drunk), but there's an easier way to solve the task anyway.
>Enjoy !
>K71 

Basically, in the second part, we need to obtain the token of "administrator", choose "generate nuclear bomb codes", and give that token. Then the server will show the master key, that is the flag. If we try to register "administrator" it says that this name is not allowed.

By reversing the binary we can notice that the president name is first padded, and then block encrypted.
The padding schema is something like:
```
number_of_blocks (1 byte) + president_name + padding
where the padding contains the number of bytes needed to fill the last block (of size 16 byte), repeated
```

For example, for admnistrator, the token before the encryption is:
`"\x01" "administrator" \x02\x02"`

The encryption algorithm seems to be Feistel-based. The core is something like this.
```
 for(int i=0;i<8;i++)
      left[i] ^= DATA2[right[i-1]] ^ right[DATA[8 * lowpart + i]] ^ DATA3[8 * highpart + i];
```

We tried to see if we could reverse the Feistel F function, without succeeding. Also, we noticed a buffer underflow in the code, that reads out of "right" when `i=0`.

We then noticed that by encrypting a message with length `15` (block size -1) no new blocks are added, so
`administrator` and `administrator\x02\x02` are mapped to the same padded message:
`\x01administrator\x02\x02`
and are encrypted in the same way.  
Thus, by asking the server to register a new president, `administrator\x02\x02`, we can obtain the token of `administrator` and use it to get the flag.

