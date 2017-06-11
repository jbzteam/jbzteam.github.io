---
layout: post
title:  "SHA Teaser 2017 - No Commnt.. Again"
date:   2017-06-11 20:42
categories: CTF
tags: [SHATeaser2017]
categories: [Reversing]
author: jbz
---
There might be something hidden in this file, can you find it?
[https://github.com/jbzteam/CTF/blob/master/SHATeaser2017/NoComment..Again/NoComment.exe](https://github.com/jbzteam/CTF/blob/master/SHATeaser2017/NoComment..Again/NoComment.exe)
 

In this challenge a windows executable is given and it is asked to find the flag. When executed it asks for a password:

```
$ wine SHA_Teaser_bin100_4d128dfbfedbd7e9a7fc47f9b7c9af9d.exe

[*] SHA2017 CTF Teaser BIN 100
No comment... again...

[*] What is the secret?
```

By using the string command it is possible to notice that the executable has been created using PerlApp, a program that embeds a perl source and a perl interpreter into a single executable:

```
$ strings SHA_Teaser_bin100_4d128dfbfedbd7e9a7fc47f9b7c9af9d.exe 
...

PerlApp::lic
PerlApp::LoadLibrary
PerlApp::_clean
PerlApp::_dyndll
PerlApp::_dlmap
PerlApp::_use
PerlApp::_check
PerlApp::_init
PerlApp::no_linestr
PerlApp::get_temp_dir
PerlApp::dl_reg
PerlApp::bfs
PerlApp::exe

...
```

 

Also, it is possible to notice that the source code is not embedded in the executable as plaintext, but that maybe it is generated at runtime with some sprintf:

```
$ strings SHA_Teaser_bin100_4d128dfbfedbd7e9a7fc47f9b7c9af9d.exe | grep "%s"

...

-e#line 1 "%s"
PERL5DB=BEGIN { $PerlApp::P=$^P; $^P=0; delete %s; PerlApp::_init(%ld); eval %s('%s'); die $@ if $@; $^P=$PerlApp::P;}BEGIN { require 'perl5db.pl' }
-eBEGIN { PerlApp::_init(%ld); eval %s('%s'); die $@ if $@ }

...

```

By opening the executable with IDA, we can notice that in the main function some work is done to manage the command line arguments, and then the function sub_40593F is called:

![50493f](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/sub_40593F.png)

By decompiling that function we can notice that it just calls sub_40513E:

![50493f decompiled](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/func1decompiled.png)

And then, decompiling sub_40513e we can find the same string saw before using the strings command:

![40313e](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/func2.png)

Now, let's open the executable with ollydbg and set a breakpoint on this function:

![olly1](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/ollydbg1.png)


By pressing F8 some times in order to execute the function step by step, we can find in the stack a pointer to the perl source:

![olly2](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/ollydbg2.png)

By doing right click & follow in dump on the source address, we can see the password:

![password](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/password.png)

The password is `SuPeRS3cr3tsTuFf?!`, but, the challenge is not completed!

```
$ wine SHA_Teaser_bin100_4d128dfbfedbd7e9a7fc47f9b7c9af9d.exe

[*] SHA2017 CTF Teaser BIN 100
No comment... again...

[*] What is the secret? SuPeRS3cr3tsTuFf?!

[*] Yes, that is correct! However that was not the goal of this challenge.
Did you know that compiled code does not contain any comments?
```

By scrolling down in the source, we can see the aforementioned comment:

![comment](https://raw.githubusercontent.com/jbzteam/CTF/master/SHATeaser2017/NoComment..Again/comment.png)

By exporting all the source and saving it to a file we can find the flag, in ascii art:

```

1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
73
74
75
76
77
78
79
80
81
82
83
84
85
86
87
88
89
90
91
92
93
94
95
96
97
98
99
100
101
102
103
104
105
106
107
108
109
110
111
112
113
114
115
116
117
118
119
120
121
122
123
124
125
126
127
128
129
#!/usr/bin/perl
 
print "\n[*] SHA2017 CTF Teaser BIN 100\n".
      "      No comment... again...\n\n";
 
$secret = "SuPeRS3cr3tsTuFf?!";
 
print "[*] What is the secret? ";
$answer = <STDIN>
chomp($answer);
 
if ($answer eq $secret) {
  print "\n[*] Yes, that is correct! However that was not the goal of this challen
    ge.\n".
        "    Did you know that compiled code does not contain any comments?\n";
} else {
    print "\n[*] Isn't that cute...but it is WRONG!\n";
}
 
#  W e l l ,    w e l l,    t h e r e    i s    a    c o m m e n t    a g a i n  
    . . . .
#
# .----------------. .----------------. .----------------. .----------------. 
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |  _________   | | |   _____      | | |      __      | | |    ______    | |
#| | |_   ___  |  | | |  |_   _|     | | |     /  \     | | |  .' ___  |   | |
#| |   | |_  \_|  | | |    | |       | | |    / /\ \    | | | / .'   \_|   | |
#| |   |  _|      | | |    | |   _   | | |   / ____ \   | | | | |    ____  | |
#| |  _| |_       | | |   _| |__/ |  | | | _/ /    \ \_ | | | \ `.___]  _| | |
#| | |_____|      | | |  |________|  | | ||____|  |____|| | |  `._____.'   | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |       __     | | |     ____     | | |    ______    | | |     ____     | |
#| |     .' _/    | | |   .'    '.   | | |  .' ____ '.  | | |   .' __ '.   | |
#| |     | |      | | |  |  .--.  |  | | |  | (____) |  | | |   | (__) |   | |
#| |    < <       | | |  | |    | |  | | |  '_.____. |  | | |   .`____'.   | |
#| |     | |_     | | |  |  `--'  |  | | |  | \____| |  | | |  | (____) |  | |
#| |     `.__\    | | |   '.____.'   | | |   \______,'  | | |  `.______.'  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |   ______     | | |     ____     | | |   _    _     | | |   _______    | |
#| |  |_   _ \    | | |   .'    '.   | | |  | |  | |    | | |  |  ___  |   | |
#| |    | |_) |   | | |  |  .--.  |  | | |  | |__| |_   | | |  |_/  / /    | |
#| |    |  __'.   | | |  | |    | |  | | |  |____   _|  | | |      / /     | |
#| |   _| |__) |  | | |  |  `--'  |  | | |      _| |_   | | |     / /      | |
#| |  |_______/   | | |   '.____.'   | | |     |_____|  | | |    /_/       | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |      __      | | |      __      | | |     __       | | |    ______    | |
#| |     /  \     | | |     /  \     | | |    /  |      | | |  .' ____ '.  | |
#| |    / /\ \    | | |    / /\ \    | | |    `| |      | | |  | (____) |  | |
#| |   / ____ \   | | |   / ____ \   | | |     | |      | | |  '_.____. |  | |
#| | _/ /    \ \_ | | | _/ /    \ \_ | | |    _| |_     | | |  | \____| |  | |
#| ||____|  |____|| | ||____|  |____|| | |   |_____|    | | |   \______,'  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |    ______    | | |   _______    | | |   _______    | | |     ______   | |
#| |   / ____ `.  | | |  |  ___  |   | | |  |  _____|   | | |   .' ___  |  | |
#| |   `'  __) |  | | |  |_/  / /    | | |  | |____     | | |  / .'   \_|  | |
#| |   _  |__ '.  | | |      / /     | | |  '_.____''.  | | |  | |         | |
#| |  | \____) |  | | |     / /      | | |  | \____) |  | | |  \ `.___.'\  | |
#| |   \______.'  | | |    /_/       | | |   \______.'  | | |   `._____.'  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |     ______   | | |   _______    | | |     ____     | | |      __      | |
#| |   .' ___  |  | | |  |  ___  |   | | |   .'    '.   | | |     /  \     | |
#| |  / .'   \_|  | | |  |_/  / /    | | |  |  .--.  |  | | |    / /\ \    | |
#| |  | |         | | |      / /     | | |  | |    | |  | | |   / ____ \   | |
#| |  \ `.___.'\  | | |     / /      | | |  |  `--'  |  | | | _/ /    \ \_ | |
#| |   `._____.'  | | |    /_/       | | |   '.____.'   | | ||____|  |____|| |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------.
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |  _________   | | |     __       | | |     ______   | | |   _    _     | |
#| | |_   ___  |  | | |    /  |      | | |   .' ___  |  | | |  | |  | |    | |
#| |   | |_  \_|  | | |    `| |      | | |  / .'   \_|  | | |  | |__| |_   | |
#| |   |  _|  _   | | |     | |      | | |  | |         | | |  |____   _|  | |
#| |  _| |___/ |  | | |    _| |_     | | |  \ `.___.'\  | | |      _| |_   | |
#| | |_________|  | | |   |_____|    | | |   `._____.'  | | |     |_____|  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------. 
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |     ____     | | |      __      | | |     ____     | | |    ______    | |
#| |   .' __ '.   | | |     /  \     | | |   .'    '.   | | |   / ____ `.  | |
#| |   | (__) |   | | |    / /\ \    | | |  |  .--.  |  | | |   `'  __) |  | |
#| |   .`____'.   | | |   / ____ \   | | |  | |    | |  | | |   _  |__ '.  | |
#| |  | (____) |  | | | _/ /    \ \_ | | |  |  `--'  |  | | |  | \____) |  | |
#| |  `.______.'  | | ||____|  |____|| | |   '.____.'   | | |   \______.'  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------' 
# .----------------. .----------------. .----------------. .----------------. 
#| .--------------. | .--------------. | .--------------. | .--------------. |
#| |      __      | | |  ________    | | |    _____     | | |     ______   | |
#| |     /  \     | | | |_   ___ `.  | | |   / ___ `.   | | |   .' ___  |  | |
#| |    / /\ \    | | |   | |   `. \ | | |  |_/___) |   | | |  / .'   \_|  | |
#| |   / ____ \   | | |   | |    | | | | |   .'____.'   | | |  | |         | |
#| | _/ /    \ \_ | | |  _| |___.' / | | |  / /____     | | |  \ `.___.'\  | |
#| ||____|  |____|| | | |________.'  | | |  |_______|   | | |   `._____.'  | |
#| |              | | |              | | |              | | |              | |
#| '--------------' | '--------------' | '--------------' | '--------------' |
# '----------------' '----------------' '----------------' '----------------'  
# .----------------. .----------------. 
#| .--------------. | .--------------. |
#| |    ______    | | |     __       | |
#| |  .' ____ \   | | |    \_ `.     | |
#| |  | |____\_|  | | |      | |     | |
#| |  | '____`'.  | | |       > >    | |
#| |  | (____) |  | | |     _| |     | |
#| |  '.______.'  | | |    /__.'     | |
#| |              | | |              | |
#| '--------------' | '--------------' | 

```

 

The flag is `FLAG{098B047AA19375CC70AE1C48A03AD2C6}`
