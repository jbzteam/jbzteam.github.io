---
layout: post
title:  "HackDatKiwi CTF 2017 - serialnumber"
date:   2017-10-16 23:00
categories: [HackDatKiwi2017]
tags: [Web]
author: jbz
---

This challenge has been a pain in the a%%, no doubts about it.  
It was fairly easy (hence the 60pts) in the sense that when you understood what was wrong you could pwn it with just a word.

Anyway, you were given a WebApp made of a few php files. The interesting ones were `user.php`, `db.php` and `signup.php`.

You can signup to the WebApp using the `signup.php` script, but you get to see the flag only if the serial number you provide to this script is valid **AND** is not used by another user.  

Unluckily (and pretty obviously) the valid serial numbers have been used by other two users, whose passwords have been MD5ed and can't be cracked by any online hash cracker. Well, 5h1t.

By taking a look at `user.php` you could understand that the flag would have been printed if you managed to break the following code:

```
function isadmin($user)
    {
        return sql("select ? in (select serialnumber from serialnumbers) as result",$user->serialnumber)[0]->result!=="0";
    }
```

I have been literally trying everything I could come up with (like *hoola-baloo-not-working SQL injections* and so on) but nothing worked. 

Then, out of ideas and out of despair one light turned on:
"What if I put NULL as a serial number?". 

And it broke, the flag laughing at me on the screen. ***WTF?***  

Turns out that MySQL has a rather strange behavior: to comply with SQL standard the IN statement returns NULL if no match is found in the database AND one of the entries is NULL.  
It means that, by fetching NULL from the database, result == NULL and != 0, showing the flag. 

Even now I'm still WTFing about it.
