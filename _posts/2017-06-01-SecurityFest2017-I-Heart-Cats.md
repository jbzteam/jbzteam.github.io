---
layout: post
title: "SecurityFest2017 - I Heart Cats"
date: 2017-06-01 21:55
categories: CTF
tags: [SecurityFest2017]
categories: [Misc]
author: jbz
---

We got this cute cat page. There is something odd in it. But I can't quite say what.


Download: [https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/IHeartCats/badhtml.zip](https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/IHeartCats/badhtml.zip)

  
Opening the two index.html files given, we can see that one is completely messed up with the indentation. Highlighting all the syntax in sublime text, we can see that there is a pattern with the tab and spaces. At first, a solution might have been whitespace syntax, but this wasn't the case. So another solution was to think that the `"\t"` was `1` and `8 spaces` were `0`. Infact with the following script: 


```
def f():
    s=""
    x = open("index.html","r")
    for line in x:
        i = 0;
        while i < len(line):
            if(line[i] == "\t"):
                s+="1"
            elif(i+7 < len(line) and line[i:i+7] == " "*7):
                i+=7
                s+="0"
            i+=1
    return s
```


 
We get the following output:
```
0101001101000011010101000100011001111011010101110110100000110001001101110011001100110101011100000011010001100011001100110011010101011111001101000111001000110011010111110011100000110100011001000101111100110100011101010010000101111101  
```

Translating from binary to text, the final output is:
```
SCTF{Wh1735p4c35_4r3_84d_4u!}
```
