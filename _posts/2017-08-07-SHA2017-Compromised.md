---
layout: post
title:  "SHA2017CTF - Compromised"
date:   2017-08-07 00:10
categories: CTF
tags: [SHA2017CTF]
categories: [Forensics]
author: jbz
---


>We think our system got compromised, our hosting company uses some strange logtool. 
>Are you able to dig into the logfile and find out if we are compromised?

>Challenge created by the Digital and Biometric Traces division of the Netherlands Forensic Institute.
[download](https://github.com/jbzteam/CTF/blob/master/SHA2017/Compromised/compromised.tgz)

Extracting the archive we got `FOR100.scap` file the `scap` extension is the commonly used by [sysdig](https://www.sysdig.org/) a system analyzer

Using `csysdig -r FOR100.scap` we were able to process the logfile with a pratical interface

![cysdig](https://raw.githubusercontent.com/jbzteam/CTF/master/SHA2017/Compromised/csysdig.png)

Looking for the files we found the execution of `/tmp/challenge.py`

![challenge](https://raw.githubusercontent.com/jbzteam/CTF/master/SHA2017/Compromised/challenge.png)

looking deeper we can see that it's called with a base64 as argument

![challenge_arg](https://raw.githubusercontent.com/jbzteam/CTF/master/SHA2017/Compromised/challenge_executions.png)

`cnKlXI1pPEbuc1Av3eh9vxEpIzUCvQsQLKxKGrlpa8PvdkhfU5yyt9pJw43X9Mqe`

using the `Echo` function of `csysdig` we were able to obtain the source of `challenge.py`

![source](https://raw.githubusercontent.com/jbzteam/CTF/master/SHA2017/Compromised/source.png)

```
from Crypto.Cipher import AES
import base64
import sys
obj = AES.new('n0t_just_t00ling',AES_MODE_CBC,'7215fc61c2edd24')
ciphertext = sys.argv[1]
message = obj.decrypt(base64.b64decode(ciphertext))
```

executing the script with the previously found argument we got the flag

```
b'Congrats! flag{1da3207f50d82e95c6c0eb803cdc5daf}'
```
