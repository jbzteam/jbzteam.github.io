---
layout: post
title: "SecurityFest 2017 - Alienise"
date:   2017-06-01 21:10
categories: [SecurityFest2017]
tags: [Web]
author: jbz
---

Another smug cloud service boasting abut their security. Care to prove them wrong?

Service: http://alieni.se:3002/

Author: avlidienbrunn

When you visit http://alieni.se:3002/ you notice that there is a CDN service on cdn.alieni.se which uses Amazon S3 and is behind Amazon Cloudfront.

If you vist http://cdn.alieni.se/WEB-INF you are redirected to http://cdn-origin.alieni.se.s3.amazonaws.com/WEB-INF/ and you can get the S3 bucket name: **cdn-origin.alieni.se**

Now you just need to connect to the bucket via `awscli` and try to list its content.

```bash
smaury@hitch-hicker:$ aws s3 ls s3://cdn-origin.alieni.se
                            PRE css/
                            PRE font-awesome/
                            PRE js/
2017-05-14 15:18:04         36 flag_9182quwaisjnzkmasj.txt
```

As you can see the S3 bucket's ACL are screwed up and you can list content without being authenticated.

To get the flag you just need to browse http://cdn-origin.alieni.se.s3.amazonaws.com/flag_9182quwaisjnzkmasj.txt

**SCTF{4LL_aUthenT1c4teD_Us3rs=pwn3d}**
