---
layout: post
title: "SecurityFest 2017 - 2bright"
date:   2017-06-01 21:54
categories: [SecurityFest2017]
tags: [Reversing]
author: jbz
---



In ancient times, giants ruled the world. Thought long gone, some giants has once again appeard, and might have even been here all the time. And though old still shine bright - maybe too bright? Note: Flag does not follow the format

Solves: 8

Download: [https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/2bright/2bright.tar.gz](https://github.com/jbzteam/CTF/blob/master/SecurityFest2017/2bright/2bright.tar.gz)

By importing the given file on `Audacity` using `8 bit pcm` as encoding  and `1` as channel we can better understand the structure of the file. By zooming on about half the file we can notice the following waveform:

![wave](https://raw.githubusercontent.com/jbzteam/CTF/master/SecurityFest2017/2bright/wave.png)
This suggests that in some way each byte at position i has been "encrypted" with some key dependent on i. 

After some trials, we noticed that by transforming the data in the following way, something useful results.

```
for(int i=0;i<512;i++){
    result[i] = data[i] ^ (512-i);
} 
```
 
The obtained waveform is the following:

![wave_manipulated](https://raw.githubusercontent.com/jbzteam/CTF/master/SecurityFest2017/2bright/wave_manipulated.png)

 By removing all bytes at position `x*64-1` and writing the result in binary, 3 bytes per line, replacing zeros with spaces, we obtain the following ascii art:

```
 1111111  1     1   111111   
    1     1     1  1         
    1     1     1  1         
    1     1     1  1         
    1     1111111  11111     
    1     1     1  1         
    1     1     1  1         
    1     1     1  1         
    1     1     1  1         
    1     1     1   111111   
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
           1111111  1        
           1        1        
           1        1        
           1        1        
           1111     1        
           1        1        
           1        1        
           1        1        
           1        1        
           1        1111111  
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
  11111    11111             
 1     1  1     1            
 1     1  1     1            
 1     1  1          11      
 1111111  1  111     11      
 1     1  1     1            
 1     1  1     1    11      
 1     1  1     1    11      
 1     1  1     1            
 1     1   11111             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
           1111111  11111    
           1       1     1   
           1       1     1   
           1       1     1   
           1111    1111111   
           1       1     1   
           1       1     1   
           1       1     1   
           1       1     1   
           1       1     1   
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
   11111   111111   1        
     1     1     1  1        
     1     1     1  1        
     1     1     1  1        
     1     111111   1        
     1     1 1      1        
     1     1  1     1        
     1     1   1    1        
     1     1    1   1        
   11111   1     1  1111111  
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
   11111   11111   1     1   
     1    1     1  1     1   
     1    1     1  1     1   
     1    1        1     1   
     1    1  111   1111111   
     1    1     1  1     1   
     1    1     1  1     1   
     1    1     1  1     1   
     1    1     1  1     1   
   11111   11111   1     1   
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
 1111111            111111   
    1                     1  
    1                     1  
    1                     1  
    1                 1111   
    1                     1  
    1                     1  
    1                     1  
    1                     1  
    1               111111   
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
                             
   11111   1     1  111111   
  11    1  1     1  1     1  
  1 1   1  1     1  1     1  
  1 1   1   11111   1     1  
  1  1  1     1     111111   
  1  1  1     1     1 1      
  1   1 1     1     1  1     
  1   1 1     1     1   1    
  1    11     1     1    1   
   11111      1     1     1  
                             
```

*THE FLAG: FAIRLIGHT 30YR*

It is actually accepted if written without spaces.

Actually, the given file contains other stuff, that we couldn't understand. Also, a given hint said that we needed to use a debugger, we don't know why.

And now, the solution in 1 line :D

`od -j 6145 -N 512 -t u1 -An -w1 -v 2bright | awk 'BEGIN {i=0} { c=xor($1,(512-NR+1))%256; if(c>127)c-=256; if(NR%64!=0)printf "%c",c }' | xxd -b -c 3 | cut -b 10-38 |tr 0 ''`
