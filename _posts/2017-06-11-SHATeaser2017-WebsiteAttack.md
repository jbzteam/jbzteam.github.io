---
layout: post
title:  "SHA Teaser 2017 - WebsiteAttack"
date:   2017-06-11 19:21
categories: [SHATeaser2017]
tags: [Forensics]
author: jbz
---
Our website received an attack in 2013, we managed to capture the attack in this pcap. Can you find out if we leaked some sensitive information? (pcap file attached)


In the PCAP file we can see a lot of HTTP communications between 2 local IP addresses (a client and a server).
The client at the very first time does 2 search request in the shop exposed by the server, than he tries to inject some SQL commands, but gets an error.



What can be noticed is that when the client try to make a search a 302 reply comes back with a `what` set, having an hex charset.


```
GET /?action=search&words=kl&sort=stock HTTP/1.1
Host: 10.5.5.208:5000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.5.5.208:5000/
Connection: keep-alive

HTTP/1.1 302 FOUND
Server: gunicorn/19.7.1
Date: Thu, 01 Jun 2017 20:10:29 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 289
Location: http://10.5.5.208:5000/?action=display&what=ce3926706794d911

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href="?action=display&amp;what=ce3926706794d911">?action=display&amp;what=ce3926706794d911</a>.  If not click the link.
```


If you try to search the URL structure you can find that in ebCTF2013's teaser this challege was yet used, but it was a web challenge. [http://lmgtfy.com/?q=%22GET+%2F%3Faction%3Ddisplay%26what%3D%22](http://lmgtfy.com/?q=%22GET+%2F%3Faction%3Ddisplay%26what%3D%22)

So we can just use their approach to find what is the xor key used here.

By investigating the the PCAP we can find that the client made a search request with a lot of "A", so we can use that one to make the XOR between the HEX(search) and the what parameter to get the key.


```
41414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141414141 ^ e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479d5e95af4796e7573a65e6849952032e4146d4252bafb3b38212df186497a7479 = a5552c0313fbba7a79606cb0c7083b353894a81bb5382f3432e71f2908d46173a5552c0313fbba7a79606cb0c7083b353894a81bb5382f3432e71f2908d46173a5552c0313fbba7a79606cb0c7083b353894a81bb5382f3432e71f2908d46173a5552c0313fbba7a79606cb0c7083b353894a81bb5382f3432e71f2908d46173a5552c0313fbba7a79606cb0c7083b3538
```

Now we have the xor key `a5552c0313fbba7a79606cb0c7083b353894a81bb5382f3432e71f2908d46173` and we can decrypt all the what parameters using the perl script by f00l.de (https://f00l.de/blog/ebctf-teaser-2013-web200/) with our key.


```
#!/usr/bin/perl
 
$what = $ARGV[0];
@xor = (0xa5,0x55,0x2c,0x03,0x13,0xfb,0xba,0x7a,0x79,0x60,0x6c,0xb0,0xc7,0x08,0x3b,0x35,0x38,0x94,0xa8,0x1b,0xb5,0x38,0x2f,0x34,0x32,0xe7,0x1f,0x29,0x08,0xd4,0x61,0x73,0xa5,0x55,0x2c,0x03,0x13,0xfb,0xba,0x7a,0x79,0x60,0x6c,0xb0,0xc7,0x08,0x3b,0x35,0x38,0x94,0xa8,0x1b,0xb5,0x38,0x2f,0x34,0x32,0xe7,0x1f,0x29,0x08,0xd4,0x61,0x73,0xa5,0x55,0x2c,0x03,0x13,0xfb,0xba,0x7a,0x79,0x60,0x6c,0xb0,0xc7,0x08,0x3b,0x35,0x38,0x94,0xa8,0x1b,0xb5,0x38,0x2f,0x34,0x32,0xe7,0x1f,0x29,0x08,0xd4,0x61,0x73,0xa5,0x55,0x2c,0x03,0x13,0xfb,0xba,0x7a,0x79,0x60,0x6c,0xb0,0xc7,0x08,0x3b,0x35,0x38,0x94,0xa8,0x1b,0xb5,0x38,0x2f,0x34,0x32,0xe7,0x1f,0x29,0x08,0xd4,0x61,0x73);
 
print "WHAT = $what\n";
 
for (pos=0; $pos < length($what); $pos+=2) {
  $char = substr($what, $pos, 2);
  $int = hex($char);
  $res = $int ^ $xor[$pos/2];
 
  print chr($res);
}
 
print "\n";
```

Now we can extract all the requests containing `what=` from wireshark (`http contains "what="`), use a grep to get the what parameter content, decrypt all of them, grep for `secret_flag`, so we can get only the query used to get the flag from the DB with the SQLi and finally extract only the last request for each `SUBSTR` index, so we can get the flag.

```
grep -Eo "af\w+" packets > what
```

```
while read line; do ./dec.pl $line; done < what | grep secret_flag > secret_flag
```

```
while read line; do NUM=$(echo $line | grep -Eo "\(flag,\w,\w\)" | cut -d, -f2); if [[ $OLDNUM != "" && $NUM != $OLDNUM ]];then echo $CHAR; fi; OLDNUM=$NUM; CHAR=$(echo $line | cut -d"'" -f2); done < secret_flag
f
l
a
g
{
7
3
0
7
e
3
e
e
8
d
a
1
9
8
c
a
4
a
7
f
9
b
1
f
8
b
0
1
8
d
8
e
}

```

flag{7307e3ee8da198ca4a7f9b1f8b018d8e}
