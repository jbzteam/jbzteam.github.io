---
layout: post
title:  "INS'hAck CTF 2018 - music is frequency"
date:   2018-04-09 23:00
categories: [INShAck2018]
tags: [Crypto]
author: jbz
---

This challenge was pretty fun to solve, credits to the creator!!

We are given the initial description of the challenge and a zip file:

```
Find a way to decrypt our rsa private key to get your reward.

Because we are pretty bad musicians, we have decided to not take into account any rhythm and to round all used number to the closest.```

The zip file contains a pdf of sheet music for Frere Jacques song and two files:

 * `flag.enc` the flag encrypted
 * `privatekey.bin` the privatekey encrypted, that's been used to encrypt the flag

From the description of the challenge we instantly thought about using the frequency of each notes of the song to decrypt the key, but it wasn't right.

We thought there was something in the pdf, but we didn't find anything. 

After a little bit of struggling we used `hexdump` on
`privatekey.bin` and what we found? See it yourself:

```
jbz:src jbz$ hexdump privatekey.bin 
0000000 1d 1d 1d 1d 1d 72 75 76 79 7f 10 63 62 70 10 61
0000010 62 79 66 71 64 75 10 7a 74 69 1d 1d 1c 1d 1d 3a
0000020 7d 79 79 75 5f 47 79 73 70 71 7a 72 70 61 75 71
...
...
0000660 76 69 07 4a 62 61 5f 66 6b 79 52 41 3b 1d 1d 1d
0000670 1d 1d 75 7e 74 10 62 62 71 11 60 63 78 67 71 65
0000680 75 10 7b 75 69 1d 1d 1c 1c 1d                  
```

The first two and the last two rows have something special:

We noticed that the key starts with  `1d 1d 1d 1d 1d` - `1d 1d 1c 1d 1d` and ends with `1d 1d 1d 1d 1d` - `1d 1d 1c 1c 1d`. This reminded us of the `-` in the RSA private key format's header, specifically: `-----BEGIN RSA PRIVATE KEY-----`.  
Also the number of byte between the `1d` block were matching with the lenght of `BEGIN RSA PRIVATE KEY`.

We ended up xoring this header string with the hex that we got from the first rows of the key and we got a nice result:
`0000000101011101000000011000100`

By analyzing this string, we noticed that the numbers of `0` is always repeated, so it looks like a padding, and the other part were some numbers like `101011101` that is the binary representation of the decimal `349`.

We went back and check if this was a frequency of the first note **F** and indeed it was. Eureka.

So we xored the rest of the privatekey using all the frequency of the notes and we got the privatekey:

```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzM+Z7PPPj8l6coIATywrjehN1WljdDbZ7icA3YQNBcovrovh
BU3xcXzOuHzsb05TK5wQuwB2mYUlCH/TcCChz4EOy5hymb/MIKmYRyjljNW6BMbU
fWKBvIMpcTrM7jnRbe2miFzsiLpxn6OV32cjRnytieiMFFWFCmylLBJG5vpq7m89
5gMgpw4wWn88GMQUODxmkN8MU4GU+wwEVi4A0vMBJUxNJVx8ZF1n/6MUVyhOp3Ch
aiQ1S1EartEiV0yiX4MLNz3J83chmvH5jXqMDUN1ELcpTCc11uTW55cGz1shFnpQ
7NQYZd7CovByiDbwyuM86nJb/4QDDRuiGoSrdQIDAQABAoIBACmUaAKECPp/A93l
aJyqMflwVQTjjW5ViG7h+jn+igpH3uBHw5opFcBdfzZTHkkGlLoAyCC+2lUWg8sy
8EEOTutqnw9UVsfB+XYUGDcyJVAvP8GigBcofYBA/JPhRSOEF3GC0tFSVC758wFe
25lsPewcebrKvE2Qgx73qZzF5SEVDlu8QzUoTo1cwPG5Fax0zGITtunxvagA6+3d
i+JYwY/NqOKa5/Nq4/Y1Az4HChhdCRmJodUG5x8kwGfWiEPQhWmOJaZqkzKHZ3wK
nbt46sVpqRh2dvs6a8uA4yE1ZNrQDfjY6BynWg7EJuM+WdQ/2ZO2A/Iq3YNK5Z9u
PpFLx4ECgYEAz1cjfOhDT16ma8GzM+ocIRlt9hOKpveJ9G8oNpP5ZiQHNXTDdwje
eYILo6SzJCx0w3yuAC3+iB4JLv9x8WfenXEoQWiEiTRIxvRWCpLLdkNRRCwtvsvT
8vMiXa9KVYpmje8VQzbgWmEDbi3uis44AzaGhP4iALjcWHTSezEyuJUCgYEA/OB+
29fpbAFS2OMHHPO2TnWPypAOxVZ0Cj2gxffWNc/RmHcav6G4HIfAxz2W6IBNMUM4
eR/PeXTcBsPOjjBt+fZZHENbibm5bU5PjTICGtfFnotOVoQRyLsSQNefj84zzfS3
cZ4uQmTdYEhYQcMpIGwjKARZccP7cV29AFyMD2ECgYAQtFSHm67Qli+SPujRJete
P048pRZmnUrgBpSW0RUmxYBPLjkRPgWuhGuro3lLUMmXdlQOb6YyETlsL+heKqAk
zxkPK/yBkVTLsqO79leuD35cn7KPzJwm1q/OHHFAswXQKZLs917b6TT9i3XMeRDK
MXpk/JSAumQGPGM4yZ3sgQKBgQDIbIo/Zn6cWuQ2AKJ3oPYic20XKFx8rcvk/fl6
TrdaCS/fPq9VqTCKdFIn2DnOZzpHTDbrUXoYkrV9Kx6AdgQEdOslyoE3xJsh9kp4
52Thr5jy0wiw65ZI2XRbLktKKC3JFCd9Btk1SEppcI16+dqT1wF6SxA1ahbVQG13
ZuKfoQKBgAxyI0Vhslf3oGq0yf9Ngy35v9eJ3akFqmIS/l2ZpPIRrpICXOxSacUo
vfQrN4afh4AP/nAYDjkm7FFbp1B5p2GBzyXlAJtLpdeAS/5pVpus/LfCOCD6fe2u
c8F27mqdE+zVtiKPolkHoqki+1pizR7sed2UhlaoFY7zRQoWZIcp
-----END RSA PRIVATE KEY-----
```

Having the privatekey we used openssl to decrypt the flag:

```
$ base64 -d flag.enc > flag.bin
$ openssl rsautl -decrypt -inkey privatekey.pem -in flag.bin -out decrypted.txt -raw
$ cat decrypted.txt 
INSA{Mus1c_15_n0t_0nly_5teg4N0}
```

Here it's the complete python script for the key recovery

```python
from Crypto.Util import strxor
def xor(a,b):
    return strxor.strxor(a,b)

begin_c = b'\x1D\x1D\x1D\x1D\x1D\x72\x75\x76\x79\x7F\x10\x63\x62\x70\x10\x61\x62\x79\x66\x71\x64\x75\x10\x7A\x74\x69\x1D\x1D\x1C\x1D\x1D'
end_c = b'\x1D\x1D\x1D\x1D\x1D\x75\x7E\x74\x10\x62\x62\x71\x11\x60\x63\x78\x67\x71\x65\x75\x10\x7B\x75\x69\x1D\x1D\x1C\x1C\x1D'

begin_p = b'-----BEGIN RSA PRIVATE KEY-----'
end_p = b'-----END RSA PRIVATE KEY-----'

print(xor(begin_c, begin_p))
#print(xor(end_c, end_p))

def note2bin(freq):
    return format(freq, '016b')
    
def repeat(s, wanted):
    return (s * (wanted//len(s) + 1))[:wanted]
    
pk = open("privatekey.bin", "rb").read()
    
keystream = ""
notes = [349,392,440,349,349,392,440,349,440,466,523,440,466,523,523,587,523,466,440,349,523,587,523,466,440,349,349,262,349,349,262,349]
for n in notes:
    keystream += note2bin(n)
keystream = repeat(keystream, len(pk)).encode()

key = xor(pk, keystream)

with open("privatekey", "w") as f:
    f.write(key.decode())
```