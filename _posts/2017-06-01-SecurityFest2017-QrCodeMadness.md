---
layout: post
title: "SecurityFest 2017 - QR Code Madness"
date:   2017-06-02 11:59
categories: CTF
tags: [SecurityFest2017]
categories: [Misc]
author: jbz
---


In the archive there were lots of .png files, containing small QRCodes.

Each file was named with an integer number between 1-1400.



We used the qr-tools python lib to decode every QR code. 

All of them were alphanumeric char, but some of them decoded to '+' and 2 of them '='

So we thought about base64, but this time we missed the file order.

Since the 2 '=' files were respectively `387.png` `189.png`, the sorting wasn't by filename.

We sorted the files for the last-modified date, the output string was ending for '==' but still no flag. :(

We looked at the last-modified date for each file and some of them had the same exact epoch time, so we took those file and sort them for filename instead.

And finally. `SCTF{Th3s3_d4mn_QR_c0d3_k33p_p0p1ng_up}`

Final script

```python
#!/usr/bin/python2

import os
import glob
from qrtools import QR
import base64

a = []
t = []
for f in sorted(glob.glob("*.png"), key=os.path.getmtime):
    mtime = str(os.path.getmtime(f))
    if mtime == '1495752115.0':
        a.append(int(f[:-4]))
    t.append(f[:-4])

a = sorted(a)
for e in t:
    a.append(int(e))

s = []
for e in a:
    c = QR(filename=str(e)+'.png')
    c.decode()
    print(f, c.data)
    s.append(c.data)
        
print(base64.b64decode(''.join(s)))
```
