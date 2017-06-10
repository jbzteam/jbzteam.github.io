---
layout: post
title:  "SHA Teaser 2017 - CryptoEngine"
date:   2017-06-10 00:00
categories: CTF
tags: [SHATeaser2017]
categories: [Crypto]
author: jbz
---


We created our own [crypto engine](https://cryptoengine.stillhackinganyway.nl/). Can you decrypt the [flag](https://cryptoengine.stillhackinganyway.nl/flag)?

![flag](https://github.com/jbzteam/CTF/raw/master/SHATeaser2017/flag.png)

## Writeup
We started trying to encrypt a simple `A` text, but the engine replied with `No text to encrypt`. So I've tried with `AAAA` and the server replied with [this image](https://cryptoengine.stillhackinganyway.nl/encrypt?text=AAAA) (Note: the service works with simple GET requests).

We found out that for every group of 3 character, a new square was added to the image. 
The color of the new square depends on those 3 character, the first one for the R channel, the second one for the G channel and the third one for the B channel.
If the string lenght wasn't divisible by 3, the remaining char were added to the end of the image (see the flag for an example).

The flag is made of 12 squares and has 2 hex bytes written as text, so it's `(12 * 3) + 2 = 38` chars long. Yay!  
That is exactly the lenght of `flag{md5(str)}`.

We then tried a dummy flag text [flag{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}](https://cryptoengine.stillhackinganyway.nl/encrypt?text=flag{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}) and the first 3 square were exactly the same colors.

![dummy flag](https://github.com/jbzteam/CTF/raw/master/SHATeaser2017/flag{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}.png)

Checking the colors manually was very painful so we started writing a python script that given a string it would download its image rappresentation and "decode" every color to RGB and then to hex.

This way it was very easy to implement a brute force that for every hex byte it would check if that RGB color was right.

When our bruteforce finished we got very excited and submitted the flag but... it was wrong! :O
We forgot the 2 hex bytes written as text on the last 2 squares!
The last digit was obviously a `}`, we guessed manually the second to last digit.

Et voila! The Flag:
`flag{deaf983eb34e485ce9d2aff0ae44f852}`

And the script

```python
import requests
import string
import shutil
from PIL import Image

def padhexa(s):
    s = hex(s)
    return s[2:].zfill(2)

def decode_image(path):
    im = Image.open(path)
    pix = im.load()  
    m = 40
    data = ""
    for i in range(3, im.size[0], m):
        r,g,b = pix[i,3]
        data += "{} {} {} ".format(padhexa(r), padhexa(g), padhexa(b))
    #print(data)
    return data.split(' ')[:-1]

def req(url):
    print(url)
    assert(len(url)>=3)
    r = requests.get('https://cryptoengine.stillhackinganyway.nl/encrypt?text='+url,stream=True)
    if r.status_code == 200:
        with open(url+'.png', 'wb') as f:
            r.raw.decode_content = True
            shutil.copyfileobj(r.raw, f)
        return decode_image(url+'.png')
    return None

def brute(stri, index):
    assert(len(stri)==38)
    s = stri
    for t in range(index, len(stri)):
        for c in string.hexdigits:
            s = s[:t]+c+s[t+1:]
            res = req(s)
            if res[t] == target[t]:
                print("found "+str(t))
                break

target = decode_image('flag.png')
brute('flag{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}',5)
```