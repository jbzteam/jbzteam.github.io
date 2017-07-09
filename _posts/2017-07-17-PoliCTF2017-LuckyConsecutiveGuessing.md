---
layout: post
title:  "PoliCTF 2017 - Lucky Consecutive Guessing"
date:   2017-07-09 17:58
categories: CTF
tags: [PoliCTF2017]
categories: Crypto
author: jbz
---

> We implemented a random number generator. We've heard that rand()'s 32 bit seeds can be easily cracked, so we stayed on the safe side.

It is required to guess the output of a rand(). The rand() source file is given. An example of a play is the following:
```
$ nc lucky.chall.polictf.it 31337
Welcome!
Do you feel lucky? Try to guess the numbers I'm thinking of.
You have one minute to reach 100 points. Good Luck!
You have 10 points.
Guess the next number:
0
0Wrong, the correct number was 1527358467.
You have 9 points.
Guess the next number:

Wrong, the correct number was 4237098583.
You have 8 points.
Guess the next number:
0
Wrong, the correct number was 3143302912.
You have 7 points.
Guess the next number:
0
Wrong, the correct number was 61247370.
You have 6 points.
Guess the next number:
```

Part of the source is the following:
```
   def __init__(self, a, b, nbits):
        self.a = a
        self.b = b
        self.nbits = nbits
        self.state = random.randint(0, 1 << nbits)

    def nextint(self):
        self.state = ((self.a * self.state) + self.b) % (1 << self.nbits)
        return self.state >> (self.nbits - 32)


    multiplier = 0x66e158441b6995
    addend = 0xB
    nbits = 85    # should be enough to prevent bruteforcing
    generator = LinearCongruentialGenerator(multiplier, addend, nbits)
```

It is a classic linear congruential generator, where the current random number is not the full state, but just the 32 most significant bits.


At the first comment here [https://crypto.stackexchange.com/questions/10608/how-to-attack-a-fixed-lcg-with-partial-output](https://crypto.stackexchange.com/questions/10608/how-to-attack-a-fixed-lcg-with-partial-output) is explained how to solve this challenge.

An here is the implementation:
```
a=0x66e158441b6995L
b=11
mod = (1<<85)

def getstate(r0,r1,r2):
  t=((1<<53)*r1 - a*(1<<53)*r0 - b + (1<<53) - 1) % mod
  for k in range(1,((1<<53)*a-1-t)/mod):
    if ((t+mod*k)%a) < (1<<53):
        state = (t+(1<<85)*k)/a + (1<<53)*r0
        if (((state *a +b)%mod)*a+b)%mod >> 53 == r2:
            return state
  return 0

def next():
  global state
  state = (state*a+b)%mod
  return state >> 53

r1 = input()
r2 = input()
r3 = input()

state = getstate(r1,r2,r3)
for i in range(1,3):
  ign=next()
for i in range(1,200):
  print next()
```

`flag{LCG_1s_m0re_brok3n_th4n_you_th!nk}`
