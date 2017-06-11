---
layout: post
title: "SecurityFest 2017 - Ranshomware"
date:   2017-06-02 12:04
categories: CTF
tags: [SecurityFest2017]
categories: [Crypto]
author: jbz
---
We found an sh ransomware on a server. Can you help us recover the server's data? 
 

This challenge provided an archive with a `ranshomware.sh` bash script, a `flag.txt` encrypted file in the `flags` folder and a `debian-40r9-amd64-businesscard.iso` encrypted file, along with some `encrypted.txt` file with an hash inside.
 
Reading the bash script we discovered those files were encrypted with AES-256-CTR mode. The key was derived directly from `/dev/urandom`.

But we noticed a bug, for every file the IV was incremented by **1**, starting from **0**.

Ideally the IV (or nonce) in AES-CTR mode should be random and not predictable, then for every block an internal couter will be concatenated with the IV.

This is working as a OneTimePad where the pad key is the AES encrypted IV.

*You should never re-use a pad key. EVER.*

This is a simple single-block scheme
![CTR Mode](https://i.stack.imgur.com/lB2tI.jpg)

Since the script is passing a full 256 bit IV to the `openssl` command, the counter is not concatenated, but it's added to the IV instead.

The IV for the `flag.txt` file will be `00000000000000000000000000000005`

The IV for the `debian.iso` will be `00000000000000000000000000000003`

The third block in the `debian.iso` will have IV equals to `00000000000000000000000000000005`, the same as the flag.

Now, if you encrypt the same thing, with the same key and the same algorithm, you will get the same ciphertext.

The third block of ciphertext for the `debian.iso` will be equals to `C = X ⊕ P`, where `C` is the ciphertext, `P` is the plain `debian.iso` and `X` is the AES encryption of the above IV with the script key.

The first block of ciphertext for the `flag.txt` file will share the same `X`.

Without the key we can't calculate `X` but fortunately we have the plain `debian.iso`, so `X = C ⊕ P` using the iso plaintext and ciphertext, then we do `P = C ⊕ X` for the flag ciphertext.

This will give us the decrypted `flag.txt` content.

```
SCTF{MISSHANDLED_IVS_ARE_AWFUL_FOR_HEALTH_0H_4lM057_11k3_1337!}
```

Here our python script:

```python
with open("debian_plain.iso") as f:
    iso_p = f.read()

with open("debian_enc.iso") as f:
    iso_e = f.read()

iso_p = iso_p[32:1024]
iso_e = iso_e[32:1024]
key = ""
for i in xrange(len(iso_e)):
    key += chr(ord(iso_p[i]) ^ ord(iso_e[i]))

with open("flag.txt") as f:
    flag = f.read()

result = ""
for i in xrange(len(flag)):
    result += chr(ord(key[i]) ^ ord(flag[i]))

print result
```

