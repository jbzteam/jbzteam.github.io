---
layout: post
title:  "SecurityFest2017 - Empty"
date:   2017-06-01 20:14
categories: [SecurityFest2017]
tags: [Forensics]
author: jbz
---


Some suspicious character left this laying around on our system , seems to be empty.

Solves: 34

Download: [https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/Empty/empty.7z](https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/Empty/empty.7z)



Extracting the archive we got a pdf file

Using `evince` we can  apparently see a white paper but selecting the area we got:

![pdf](https://raw.githubusercontent.com/jbzteam/CTF/master/SecurityFest2017/Empty/pdf.png)

Opening the PDF using  `pdfsh`

```
Welcome to the PDF shell (Origami release 2.0.2) [OpenSSL: yes, JavaScript: no]

>>> PDF.read 'empty.pdf'
[info ] ...Reading header...
[info ] ...Parsing revision 1...
[error] Breaking on: ">>\nendobj\n..." at offset 0x3949
[error] Last exception: [Origami::InvalidObjectError] Failed to parse object (no:1337,gen:0)

[info ] ...Parsing xref table...
[info ] ...Parsing trailer...
[info ] ...Propagating types...

---------- Header ----------
  [+] Version: 1.4
----------  Body  ----------
   2 0 R  ContentStream
   3 0 R  Integer
   5 0 R  FontStream
   6 0 R  Integer
   7 0 R  FontDescriptor
   8 0 R  Stream
   9 0 R  TrueType
  10 0 R  FontStream
  11 0 R  Integer
  12 0 R  FontDescriptor
  13 0 R  Stream
  14 0 R  TrueType
  15 0 R  Dictionary
  16 0 R  Resources
   1 0 R  Page
   4 0 R  PageTreeNode
  17 0 R  Catalog
  18 0 R  Metadata
---------- Trailer ---------
  [*] /Size: 19
  [*] /Root: 17 0 R
  [*] /Info: 18 0 R
  [*] /ID: [ <8AD569ADC2CC0A5BF594B43910B2294B> <8AD569ADC2CC0A5BF594B43910B2294B> ]
  [*] /DocChecksum: /6B23716413ADA1BC464C4D03D918270B
  [+] startxref: 15212
```


We can see an error regarding the object with the ID `1337`, well, this can't be just a coincidence

```
[error] Last exception: [Origami::InvalidObjectError] Failed to parse object (no:1337,gen:0)
```
So we used `VIM` and searched for the object with the ID `1337`

```
140 1337 0 obj
  141 <</Type/Font/Subtype/TrueType/BaseFont/BAAAAA+LiberationSerif-Bold
  142 /FirstChar 0
  143 /LastChar 25
  144 /Widths[/Widths[83 67 84 70 123 115 116 114 52 110 103 51 95 111 98 106 51 99 116 95 99 104 114 95 49 110 95 112 108 52 49 110 95 115 49 116 51 125]
  145 /FontDescriptor 12 0 R
  146 /ToUnicode 13 0 R
  147 >>
  148 endobj
```

We can see that the error is cause by the  line `144`

```
Widths[/Widths[83 67 84 70 123 115 116 114 52 110 103 51 95 111 98 106 51 99 116 95 99 104 114 95 49 110 95 112 108 52 49 110 95 115 49 116 51 125]
```
At this point we have an array with `125` a number really lucky for a CTF player because is `}` in dec so we converted all the numbers and we got the flag!

```
SCTF{str4ng3_obj3ct_chr_1n_pl41n_s1t3}
```
