---
layout: post
title: "WhiteHat2017 - Dai Lai Lake"
date:   2017-05-28 21:06
categories: CTF
tags: [WhiteHat2017]
categories: [Forensics]
author: jbz
---
Can you find my sensitive infomation?

Dai Lai has acquired a reputation for the land of graceful mountains and debonair water

[Download Link](https://github.com/jbzteam/CTF/blob/master/WhiteHatSummer2017/DaiLaiLake/passcode.zip)

Extracting the archive we got `passcode.apk`

Extracting the apk ad looking for some files we found a database inside the `assets` folder

```
ls assets
passcode.sqlite
```

the database contains two tables, `user` and `zadminz`:

```
sqlite> .tables
user     zadminz
```

`user` contains two users:

```
SELECT * FROM user;
1|xxx@gmail.com|1234
2|aaa@gmail.com|3333
```

`zadminz` contains the administrator email address:

```
SELECT * FROM zadminz;
1|admin_contest_05@spamdecoy.net|7777
```

[spamdecoy.net](http://spamdecoy.net) is a service for throw-away mails and allows you to log-in just with the username.

So we logged inside the admin account founding a bunch of mails, but one in particular got out attention:

![mailbox](https://raw.githubusercontent.com/jbzteam/CTF/master/WhiteHatSummer2017/DaiLaiLake/mail.png)

```
Your new PASSCODE is: check_your_db_before_building_app
```

So we tried convering it in SHA1 and we got the flag:

`WhiteHat{254eb81a7b439405a5d006eb7cfdf0cd841c6d28}`
