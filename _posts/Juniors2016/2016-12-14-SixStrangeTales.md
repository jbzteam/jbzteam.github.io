---
layout: post
title:  "Juniors2016 - Six Strange Tales"
date:   2016-12-14 03:15
categories: [Juniors2016]
tags: [Crypto]
author: jbz
---


Il testo recita:

>- Gruncle Stan, what`s the secret of the six fingered hand?  
>- Can you see these codes? When the six fingered hand touches them, one of the Gravity Falls secrets opens!  
>- Gruncle, but how should we read the secret? From left to right or right to left? Or maybe upside down?  
>- It depends on whether you are a Christian, a Muslim or a Taoist... 

La pagina presenta un'immagine contenente delle stringhe

![Challenge](https://raw.githubusercontent.com/jbzteam/CTF/master/Juniors2016/SixStrangeTales/SixStrangeTales.png)

Osservando il sorgente della pagina è possibile notare il seguente codice javascript commentato

```
<script type="text/javascript">  
<!-- 
window.addEventListener('load', function () { 
    var b = document.getElementById('img'); 
    var a = b.getContext('2d'); 
    var d = new Image(); 
    d.src = "http://i.imgur.com/GIYH3fA.png"; 
    d.addEventListener('load', function () { 
        a.drawImage(this, 0, 0); 
        k = 174; 
        l = 345; 
        m = 12; 
        n = 89;  
        o = 671; 
        p = 18; 
        q = 222; 
        r = q-1; 
        c="rgba(0,0,0,0)"; 
        if (navigator.userAgent == "Gravity Falls") c=c.replace(/(0)(\))/,"$1.5$2"); 
        a.fillStyle = c; 
        a.fillRect(q%m-6, k-3, n+r-q-2, 5-(p-q)); 
        a.fillRect(2*(q+1), p+1, n+r-q+2, l+16); 
        a.fillRect(l+r-30, o%p-5, 2*l-600, q+5-p); 
        a.fillRect(q%n+42, o%p-5, o-600+p+1, 2*(p+1)); 
        a.fillRect(176, o%p-5, 2*l-600, q/2*3+47); 
        a.fillRect(2*k+p-100, q%m-6, o-600+p+1, n+r-m/2); 
        a.fillRect(o%p-5, q%m-6, 2*l-604, k-p-4); 
        a.fillRect(2*k+p-100, q/2*3-10, 3*m+p*3, (p+1)*3); 
        a.fillRect(2*k+p-m+2, q%m-6,2*l-600, q+n+m-190); 
        a.fillRect(2*k+p-10, k-p-m/3, o-600+p+1, r+m*2/3+p); 
        a.fillRect(n-3, q-k+9, 2*(l-300), q+n+m); 
        a.fillRect(l+q-31, q+m/2,2*l-600, k-p-m/3); 
        a.fillRect(o-2*p-p/2, q%m-6, 2*l-600, q/2*3+47); 
    },false); 
},false); 
// --> 
</script> 
```
Utilizzandolo vengono evidenziat alcune strighe:

![After-Script](https://raw.githubusercontent.com/jbzteam/CTF/master/Juniors2016/SixStrangeTales/highlight.png)

```
Maiy2au0 
Is4feeh3 
aej8eeTh 
AhWae2Oh 
dawu0Aeb 
ud2juD9a 
```
provandole a combinare in maniera diversa seguendo quanto detto nella prefazione escono fuori le seguenti combinazioni

```
AhWae2OhIs4feeh3ud2juD9aaej8eeThMaiy2au0dawu0Aeb
dawu0AebMaiy2au0aej8eeThud2juD9aIs4feeh3AhWae2Oh 
Maiy2au0Is4feeh3aej8eeThAhWae2Ohdawu0Aebud2juD9a 
```

L'ultima risulterà essere la flag
