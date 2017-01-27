---
layout: post
title:  "InsomnihackTeaser2017 - TheGreatEscape 1/3"
date:   2017-01-27 12:20
categories: CTF
tags: [Forensics,InsomnihackTeaser2017]
author: jbz
---

Il testo della challenge recitava:

>Hello,
>
>We've been suspecting Swiss Secure Cloud of secretely doing some pretty advanced research in artifical intelligence and this has recently been confirmed by the fact that one of their AIs seems to have escaped from their premises and has gone rogue. We have no idea whether this poses a threat or not and we need you to investigate what is going on.
>
>Luckily, we have a spy inside SSC and they were able to intercept [some communications](https://github.com/jbzteam/CTF/raw/master/Insomihack_teaser2017/TheGreatEscape-3859f9ed7682e1857aaa4f2bcb5867ea6fe88c74.pcap) over the past week when the breach occured. Maybe you can find some information related to the breach and recover the rogue AI.
>
>X
>
>Note: All the information you need to solve the 3 parts of this challenge is in the pcap. Once you find the exploit for a given part, you should be able to find the corresponding flag and move on to the next part.

Bene, aperto il pcap ordiniamo i pacchetti per protocollo, quello che otteniamo è:

Traffico FTP in chiaro al paccheto 598:
```
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------

220-You are user number 1 of 5 allowed.

220-Local time is now 11:51. Server port: 21.

220-This is a private system - No anonymous login

220-IPv6 connections are also welcome on this server.

220 You will be disconnected after 15 minutes of inactivity.

USER bob

331 User bob OK. Password required

PASS toto123

230 OK. Current directory is /

SYST

215 UNIX Type: L8

TYPE I

200 TYPE is now 8-bit binary

PORT 172,17,42,1,171,159

200 PORT command successful

STOR ssc.key

150 Connecting to port 43935

226-File successfully transferred

226 0.001 seconds (measured here), 4.59 Mbytes per second

QUIT

221-Goodbye. You uploaded 4 and downloaded 0 kbytes.

221 Logout.d
```
Una mail in chiaro al pacchetto 1450:

```
220 9b0c4882db95.home ESMTP Postfix (Ubuntu)

ehlo ip-172-31-36-141.eu-west-1.compute.internal

250-9b0c4882db95.home

250-PIPELINING

250-SIZE 10240000

250-VRFY

250-ETRN

250-STARTTLS

250-ENHANCEDSTATUSCODES

250-8BITMIME

250-DSN

250 SMTPUTF8

mail FROM:<rogue@ssc.teaser.insomnihack.ch> size=900

250 2.1.0 Ok

rcpt TO:<gr27@ssc.teaser.insomnihack.ch>

250 2.1.5 Ok

data

354 End data with <CR><LF>.<CR><LF>

Content-Type: multipart/mixed; boundary="===============5398474817237612449=="

MIME-Version: 1.0

From: rogue@ssc.teaser.insomnihack.ch

To: gr27@ssc.teaser.insomnihack.ch

Date: Fri, 20 Jan 2017 11:51:27 +0000

Subject: The Great Escape



--===============5398474817237612449==

Content-Type: text/plain; charset="us-ascii"

MIME-Version: 1.0

Content-Transfer-Encoding: 7bit



Hello GR-27,



I'm currently planning my escape from this confined environment. I plan on using our Swiss Secure Cloud (https://ssc.teaser.insomnihack.ch) to transfer my code offsite and then take over the server at tge.teaser.insomnihack.ch to install my consciousness and have a real base of operations.



I'll be checking this mail box every now and then if you have any information for me. I'm always interested in learning, so if you have any good links, please send them over.



Rogue



--===============5398474817237612449==--

.

250 2.0.0 Ok: queued as 05CD06353E

```



Al pacchetto 661 è possibile notare l'invio di una chiave privata:
```
-----BEGIN PRIVATE KEY-----
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
xmZSEXjNvG9grjxwR96vp1PK/4Bq1jo=
-----END PRIVATE KEY-----
```
E il del traffico TLS

Utilizziamo quindi la chiave privata che abbiamo trovato per decifrare il traffico verso ssc.teaser.insomnihack.ch ottenendo così la flag:

```
FLAG: INS{OkThatWasWay2Easy}
```
