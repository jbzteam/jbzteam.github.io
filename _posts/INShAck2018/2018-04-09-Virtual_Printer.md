---
layout: post
title:  "INS'hAck CTF 2018 - Virtual Printer"
date:   2018-04-09 14:00
categories: [INShAck2018]
tags: [Forensics]
author: jbz
---

>Hey !
Someone did something really smart to retrieve stolen documents.
Will you find what it's all about?
https://virtual-printer.ctf.insecurity-insa.fr

We are given the address of a "Virtual Printer Service".
By issuing a POST req to `/print` you'll get a 2480x3508 image (that is the standard A4 @ 300 ppi) as raw PNG data. 
Again, requesting `/serial-number` with the base64 encoded S/N of the printer, will print out the flag.

Reading the challenge, we rightly thought that we would have to deal with some sort of steganographic watermarking for documents ([MIC](https://en.wikipedia.org/wiki/Machine_Identification_Code)).

On this basis, we uploaded to the Virtual Printer service [a small transparent png file](https://github.com/mathiasbynens/small/blob/master/png-transparent.png), providing us an almost untouched blank sheet.
Analyzing the printed sheet with [StegSolve](http://www.caesum.com/handbook/stego.htm), we find a matrix of dots in the blue plane 4 and 5. This same matrix is vertically repeated on 16 rows in the sheet. 

![The Dot Matrix](https://raw.githubusercontent.com/jbzteam/CTF/master/INShAck2018/VirtualPrinter/dotMatrix.png)

A first look on the matrix made us suppose we were in front of the infamous DocuColor tracking dots, but comparing the size (15 by 8 dots for DocuColor, 64 by 8 for the Virtual Printer) and the format (no column parity or separators) of the two matrix, we quickly discarded this speculation ([Thanks EFF!](https://w2.eff.org/Privacy/printers/docucolor/)).

![The Overlayed Dot Matrix](https://raw.githubusercontent.com/jbzteam/CTF/master/INShAck2018/VirtualPrinter/overlayedDotMatrix.png)

Simply decoding the matrix by 8-bit columns lead us to this output (e.g.):

```
ip:15110113147
d:8418
S/N:123456789123456789123456789
```

showing the IPv4 address and the date of the request, other than the serial number. Note that only the keys like "ip:","d:" and "S/N:" were ascii encoded, not the values. 
To make matters worse, there was a 25-seconds expiration time slot from the occurrence of the print to the submission of the S/N.

With a bit of ImageMagick and PIL, we hacked together a py script to solve it under 4 seconds. [Here's the source](https://raw.githubusercontent.com/jbzteam/CTF/master/INShAck2018/VirtualPrinter/solveVirtualPrinter.py).

This challenge was rather easy, but for many represented an issue because of the strictness of the validation side.

Here are a few takeaways:

* Use curl. It will prevent argument url encoding being applied to your parameters for POST requests (seen with python requests).
* Try to include or strip CRLF characters before encoding to a base, and see what works for you!