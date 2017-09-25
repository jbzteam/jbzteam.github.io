---
layout: post
title:  "SHA Teaser 2017 - FollowMe"
date:   2017-06-11 14:29
categories: [SHATeaser2017]
tags: [Web]
author: jbz
---
We are tracking a hacker, can you help us track the hacker down and bring him to justice?


The website locates you based on your IP address and you need to have an IP address in a specific country to solve all the 12 steps.

If you set an IP address in the X-Forwarded-For header the server uses it as your IP and geolocates you based on it.


![worldmap](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/FollowMe/followme1.png)


To solve the challenge you just need to see where you supposed to be and send an IP address which is geolocated in that country for each of the 12 country asked.


![worldmap solved](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/FollowMe/followme3.png)
