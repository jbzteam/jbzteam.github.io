---
layout: post
title:  "INS'hAck CTF 2018 - Crypt0r part3"
date:   2018-04-08 23:00
categories: [INShAck2018]
tags: [Reversing]
author: jbz
---

>You're almost done with this, try harder!
>Once you have all the needed information from previous step, go have a look here (https://gcorp-stage-4.ctf.insecurity-insa.fr/)
>Note: you should validate stage 3 to have more information on stage 4.

By loading the page at https://gcorp-stage-4.ctf.insecurity-insa.fr/ we obtain:
```
                        G-Corp Emergency Override
                                 __    _
                            _wr""        "-q__
                         _dP                 9m_
                       _#P                     9#_
                      d#@                       9#m
                     d##                         ###
                    J###                         ###L
                    {###K                       J###A
                    ]####K      ___aaa___      J####F
                __gmM######_  w#P""   ""9#m  _d#####Mmw__
             _g##############mZ_         __g##############m_
           _d####M@PPPP@@M#######Mmp gm#########@@PPP9@M####m_
          a###""          ,Z"#####@" '######"\g          ""M##m
         J#@"             0L  "*##     ##@"  J#              *#K
         #"               `#    "_gmwgm_~    dF               `#_
        7F                 "#_   ]#####F   _dK                 JE
        ]                    *m__ ##### __g@"                   F
                               "PJ#####LP"
         `                       0######_                      '
                               _0########_
             .               _d#####^#####m__              ,
              "*w_________am#####P"   ~9#####mw_________w*"
                  ""9@#####@M""           ""P@#####@M""

POST a valid override key.
```

From stage 3 we obtained a source that reads a key, and checks if it is correct or not. There is a server where if we send the right key, it sends us the flag.  
Instead of trying to understand what the program does, we can do the following.

Replace the main with this:
```
uchar nondet_uchar();
int main(int argc, char **argv)
{

    for(int i=0;i<EO_KEY_SZ;i++){
        gKEY[i] = nondet_uchar();
        if( gKEY[i] < 32 || gKEY[i] > 126 )return 0;
    }
    compute();
    assert(memcmp(gRESULT, gCOMPUT, EO_RESULT_SZ)!=0);
}
```

Start cbmc that finds the right key for us:
```$ cbmc --trace source.c | grep gKEY | cut -d '=' -f 2 | cut -d ' ' -f 1 | awk '{ printf "%c",$1 }'
sn[$p}u LDH*}|uh\HWF\PU`_#>Z(`V-1F S#??_(Pw#S?GRA)~7OsRd!05I>4OW```

And we can check that it is valid:
```$ ./stage4 check
sn[$p}u LDH*}|uh\HWF\PU`_#>Z(`V-1F S#??_(Pw#S?GRA)~7OsRd!05I>4OW
OK
```

By sending it to the server we obtain the flag.
