---
layout: post
title: "dJulkalender 2015: Writeups"
date: 2015-12-25 19:06
type: post
published: true
comments: true
categories: ctf
---

The computer science chapter at my alma mater, KTH, arranges an advent calendar called ["dJulkalendern"](https://djul.datasektionen.se).
It is a CTF-like puzzle with challenges (almost) every day until christmas and also a competition.
Last time it was arranged in 2013, I won the challenge but this year I had to settle for a third place.

The puzzles are not really security focused like regular CTF but more broader IT related puzzles.
The competiton was held in Swedish but I will still do this writeup in English since anyone might learn a thing or two from it.
This means that I will also write any clues freely translated into English.
This year, there was a puzzle everyday except Sundays and I will go through and explain them all.
To prevent this post from being too long, I will be pretty brief in my explanations. If you have any questions or solved something in a different way, please comment below.

## Day 1: Use the Source Luke

The first puzzle was simple, simply look at the source code of the page to find a hidden html tag with the phrase "The password is bananas"

Password: bananer

## Day 2: Enter the MUDtrix

This puzzle asked us to connect to a MUD-like game.
This can be done using for example netcat.
The game asks for a player name and then allows you to issue commands like "go" and "use".
The solution was to go north and "turn on" the switch to recieve a phone call with the answer.
Here is a transcript of me playing through the game.

```bash
nc 188.166.63.14 1338
```

> Mysterious Santa: What is your name?  
> $ ZetaTwo  
> Mysterious Santa: Welcome to the world. *Poof*  
> This is an open field west of a white house, with a boarded front door.  
>   
> To the east: A white house.  
> To the north: A large switchboard.  
> To the south: You'll have to cooperate  
> To the west: A shed  
>   
> $ go north  
> In front of you is a large switchboard.   
> Strangely, there's only one little switch.  
> Currently, it is turned off.  
>   
> To the south: An open field  
>   
> $ turn on  
> Your phone is ringing:  
> PHONE: ... "HJÄLP", står det.  

Password: hjälp

## Day 3: VIRUS!

In this puzzle we are asked to check if there is any cash.
To do this, we are given the Tor-URL: [http://qaizidzi2s7ks2ew.onion](http://qaizidzi2s7ks2ew.onion).
Using the Tor-browser to try to access the URL, we are redirected to Google.
To see what is going on I used cURL through Tor.

```bash
torify curl qaizidzi2s7ks2ew.onion
```

```html
<!DOCTYPE html>
<html>
    <body>
        <script>
            window.location = "http://google.se";
        </script>
        <a href="/finns_cash.html">finns cash?</a>
    </body>
</html>
```

There is a Javscript redirection in the code which explains the redirect and also a link.
If we access that link we get the answer.

```bash
torify curl qaizidzi2s7ks2ew.onion/finns_cash.html
```

```html
<!DOCTYPE html>
<!-- saved from url=(0059)https://dl.dropboxusercontent.com/u/5402898/finns_cash.html -->
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"></head><body>
        <h1>Finns cash?</h1>
        <h2>Jajamensan</h2>
</body></html>
```

Password: Jajamensan

## Day 4: Geggamoja

In this puzzle we are given a string: "D.h ok.how hai epap ycnn X.nc;. rjd u.oyapv" and a YouTube video: [https://www.youtube.com/watch?v=ETNoPqYAIPI](https://www.youtube.com/watch?v=ETNoPqYAIPI).
We are also asked where the marketing elf went.
This video is a piece by Antonin Dvorak which happens to share his name with August Dvorak, inventor of the [Dvorak keyboard layout](https://en.wikipedia.org/wiki/Dvorak_Simplified_Keyboard)
If you type the original message on a Dvorak keyboard you get that string.
Reversing the transformation we get a message "Hej svejsn jag drar till Belize och festarn" which gives us the location of the elf.

Password: belize

## Day 5: Skäggbok

In this puzzle we are given an SQLite database which is supposed to have been leaked from "Beardbook".
Opening the database in a tool such as "SQLiteBrowser" we see that there is one table called "users".
In this table we find four users. One of them is "evilelf" with password hash: "b920c9d52bc838c44c524a48ce1771d6".
[Googling this](http://tellspell.com/swedish/gl%C3%B6gg/9411/) hash gives us that this is the md5 hash of the Swedish word "glögg".

Password: glögg

## Day 7: Photoshop Skills

Here we are given two images:

A.png
![Image A](/assets/images/ctf/djul_a.png)

B.png
![Image B](/assets/images/ctf/djul_b.png)

If we put this images over each other with 50% opacity and align them so that the text in images align we start to see something.

![Images A and B](/assets/images/ctf/djul_ab_almost.png)

Tweaking this a little gives us the answer very clearly

![Solution image](/assets/images/ctf/djul_ab_final.png)

Password: basgång

## Day 8: Ett programmeringsspråk

Here we are given a completely white image:

![White image](/assets/images/ctf/djul_white.png)

Increasing the contrast in the image we get something that looks like code.

![APL code](/assets/images/ctf/djul_apl.png)

This is actually APL code and [executing it](http://tryapl.org/#?a=%7B%28+%u233F%u2375%29%F7%u2262%u2375%7D%201%202%203%2010&run) gives us the answer.
It can be a little difficult to even input those characters as code.
Luckily, this online interpreter has exactly this program as a pre-made example.

Password: fyra

## Day 9: MUDtrix reloaded

Here we are asked to connect to the MUD again.
This time we go south and find a locked door with four lights.
In the nearby rooms we also find four buttons.
Pressing each of of the buttons lights one of the lights on the door for a short period of time.

To solve this alone, simply connect five instances of netcat to the MUD and place four of your characters by the buttons and the fifth by the door. Then quickly one button in each instance and go through the door with the fifth instance.
When you get through the door, there are four directions to choose between.
Choosing the correct one (which I think was random) gives us the answer.
Here is a transcript of the last part of the game.

> /---------------\  
> |[X]|[X]|[X]|[X]|  
> \---------------/  
> At long last, you are nearing the heart of the NSA system.  
> But what's this?  
> Their final measure is confusion!  
>  
> To the north: The junction  
> To the north-south: The heart of the NSA storage facility.  
> To the east-west: This is the heart of the NSA storage facility.  
> To the north-west-south-east: This IS the heart of the NSA storage facility.  
>  
> $ go east-west  
> There's nothing here.  
> The walls are empty, no people, no windows...  
> Oh, but there is one thing.  
> A detonator lies on the ground.  
> A detonator?!  
> This has to be reported immediatelly!  

Password: detonator

## Day 10: TM28

This puzzle asks us to use TM28 (dig from Pokémon) to look in the address lookup system for the marketing elf under "jsimo.se".
Using dig to do a TXT query on "jsimo.se" gives the following:

```bash
dig jsimo.se ANY
```
> ; <<>> DiG 9.9.5-11ubuntu1-Ubuntu <<>> jsimo.se ANY  
> ;; global options: +cmd  
> ;; Got answer:  
> ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35040  
> ;; flags: qr rd ra; QUERY: 1, ANSWER: 6, AUTHORITY: 0, ADDITIONAL: 1  
>  
> ;; OPT PSEUDOSECTION:  
> ; EDNS: version: 0, flags:; udp: 512  
> ;; QUESTION SECTION:  
> ;jsimo.se.			IN	ANY  
>  
> ;; ANSWER SECTION:  
> jsimo.se.		859	IN	NS	ns1.digitalocean.com.  
> jsimo.se.		859	IN	TXT	"inget finns i toppen, leta vidare!"  
> jsimo.se.		859	IN	A	188.166.63.14  
> jsimo.se.		859	IN	NS	ns2.digitalocean.com.  
> jsimo.se.		859	IN	SOA	ns1.digitalocean.com. hostmaster.jsimo.se. 1449694817 10800 3600 604800 1800  
> jsimo.se.		859	IN	NS	ns3.digitalocean.com.  
>  
> ;; Query time: 12 msec  
> ;; SERVER: 127.0.1.1#53(127.0.1.1)  
> ;; WHEN: Thu Dec 10 14:15:40 CET 2015  
> ;; MSG SIZE  rcvd: 217  

Which tells us that there is nothing at the top (-domain).
Trying again with the "pr-tomten" sub domain gives us a binary string.

```bash
dig pr-tomten.jsimo.se ANY
```

> ; <<>> DiG 9.9.5-11ubuntu1-Ubuntu <<>> pr-tomten.jsimo.se ANY  
> ;; global options: +cmd  
> ;; Got answer:  
> ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10805  
> ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1  
>  
> ;; OPT PSEUDOSECTION:  
> ; EDNS: version: 0, flags:; udp: 512  
> ;; QUESTION SECTION:  
> ;pr-tomten.jsimo.se.		IN	ANY  
>  
> ;; ANSWER SECTION:  
> pr-tomten.jsimo.se.	1799	IN	TXT	"01110000011001010110111001110100011000010110011101101111011011100110010101101110"  
>  
> ;; Query time: 64 msec  
> ;; SERVER: 127.0.1.1#53(127.0.1.1)  
> ;; WHEN: Thu Dec 10 14:15:49 CET 2015  
> ;; MSG SIZE  rcvd: 140  

That string is simply the password encoded as an ASCII binary string.

Password: pentagonen

## Day 11: Dörren

This puzzle gives us a sentence "Tantum aranearum et machinas" which translates into "Only spiders and other machines" and an address: 188.166.63.14:53337. Setting our browser User-Agent to for example Google Bot and visiting the address gives us the password. This can be done with plugins in the browser or using cURL flags.

Password : robotfabrik

## Day 12: Brev från PR

Here we are given a link to the marketing elf's Twitter account.
[His last tweet](https://twitter.com/dJultomten/status/675605997239578624) says that he is on a nice vacation.
However, looking at the spaces between the words, we see that some of them are regular spaces and some of them are Unicode "narrow spaces".
Interpreting this as morse code gives us "...---..." which we all recognize as "SOS".

Password: sos 

## Day 14: Mot dJupet

We are given a  ".tar.gz" file containing a lot of nested directories.
Each directory contains a "password.txt" containing a single character.
If we take all the characters and discard all ".", we get the password (possibly reversed)

```bash
(for f in $(find . -name '*.txt'); do cat $f; done;) | sed 's/\.//g'
```
> clownporr

Password: clownporr

## Day 15: Recycling

Here we are given a zip-file: "tomtentsdator.zip" which is password protected.
Luckily we are given the hint that he likes to reuse passwords.
Remembering the password from day 5, we unzip the file with password "glogg".

The zip file contains a lot of different files, most of them are empty or contains garbage.
There are also some images which can be found online, indicating that they are unmodified and contain nothing of interest.
There is also a font file "coolConsoleFont.ttf" and a file "pass" containing "QWERT".
By installing the font file and using that font to type "QWERT" we get the password.

Password: danke

## Day 16: MUDception

We are again sent into the MUD. This time we can go west to find a dark room.
Pressing the button here starts a computer which allows us to play the MUD inside the MUD.
Here some knowledge of KTH's computer labs are required. Some of them are named after colors.
Next to "Crimson", in which we start is "Grey", therefore we can "go grey" to get further.

> $ nc 188.166.63.14 1338  
> Mysterious Santa: What is your name?  
> $ ZetaTwo  
> Mysterious Santa: Welcome to the world. *Poof*  
> This is an open field west of a white house, with a boarded front door.  
>  
> To the east: A white house.  
> To the north: A large switchboard.  
> To the south: You'll have to cooperate  
> To the west: A shed  
>  
> $ go west  
> This shed is very dark and damp, there are cobwebs covering every wall.  
> You feel around for the light switch and there it is, on the wall, just  
> waiting for you to press.  
>  
> To the east: An open field  
>  
> $ press  
> 
> As you press the light switch, spiders running away from your fingers, a bright  
> screen lights up the room. It's a terminal, with green letters on a black  
> background, a little dusty perhaps. There is a keyboard underneath. You could  
> type something...  
>  
> FROM CONSOLE:  
> Mysterious Santa: What is your name?  
> END OF TRANSMISSION.  
> $ type ZetaTwo2  
> FROM CONSOLE:  
> Mysterious Santa: Welcome to the world. *Poof*  
> END OF TRANSMISSION.  
> FROM CONSOLE:  
> You are standing in an open field... no, wait, a large room...  
> With computers?  
> On the wall, "CRIMSON" is written in some weird nordic language.  
> You feel a fleeting smell of donkeys...  
>  
> END OF TRANSMISSION.  
> $ type go gray  
> FROM CONSOLE:  
> This room spells of donkeys. A large group of nerds is creating some weird  
> Christmas competition about solving needlessly hard and irrelevant problems.  
> On the table lay two Star Wars tickets. The booking number is "a3JhZnRlbg==".  
> On one of the computers, an annoying video is playing:  
>     https://www.youtube.com/watch?v=8fvTxv46ano  
>  
> END OF TRANSMISSION.  

The booking number is a base 64 encoded string which decodes to "kraften"

Password: kraften

## Day 17: Hohjojuloldodetotekoktotivovenon

Here we are given the hint that something might be hidden in "the head".
Looking at the headers of the logo image we find half the solution.

```bash
 curl -I http://img.jsimo.se/djuldanke.png
```
> HTTP/1.1 200 OK  
> Server: nginx/1.4.6 (Ubuntu)  
> Date: Thu, 17 Dec 2015 11:46:11 GMT  
> Content-Type: image/png  
> Content-Length: 31005  
> Last-Modified: Mon, 30 Nov 2015 21:55:56 GMT  
> Connection: keep-alive  
> ETag: "565cc5ec-791d"  
> X-hemlighet: Kilo Mike Oscar Tango Romeo  
> X-tips: Half of the solution, you only have. Yes, hmmm  
> Accept-Ranges: bytes  

If we download the image and open it in a hex editor, we see that where the PNG data ends, there is more.
Extracting this data into another file we see that it is an MP3 file.
Playing this file we get the second half of the message: "Sierra Uniform Tango Mike Alpha"

We now have two sets of characters: "kmotr" and "sutma".
Writing these two sets as columns next to each other we can read of the password: "skumtomtar".

Password: skumtomtar

## Day 18: Spelmotorn

We are again given a zip file. This one contains a small git repository.
Using "git reflog" and "git checkout HEAD@{0}", we can recover some lost commits and extract the file "awesome.frag".

This file is a shader. To view this shader, we can use an [online viewer](https://www.shadertoy.com/new).
Copying the contents of the file into the editor gives us an image of a snowman and thus the password.

Password: snögubbe

## Day 19: Utbytesnyckel

In this puzzle we are given a file, "code.txt" which seems to contain garbage.
The title hints to a substitution cipher and the text talks about Python code.

Regular techniques such as frequency analysis doesn't really work here.
However recognizing that "iiii" must translate to some character four times in a row is a crucial first step.
The only character which regularly repeats four times in python code is "space". From here it is also easy to find the newline character. Working slowly by hand, one cna finally decode the full code.

```python
import math

result = ""
source_1 = "kfevr"
source_2 = "nakfa"
for i in range(10):
    source_num = i % 2;
    take_from = eval("source_" + str(source_num + 1));
    take_from = "".join(reversed(take_from)) if i % 2 == 1 else take_from;
    result += take_from[int(math.floor(i / 2))];
print result
```

Running this code gives us the password.

Password: kaffekvarn

## Day 21: Hotbrev

Like many of the previous puzzles we are again given an archive file containing a threat.
We are tasked with finding the sender of the mail. Using the correct flags for tar (aka. black magic) we can look at the permissions of the file.


```bash
tar -tvf mail.tgz 
```
> -rw-rw-r-- ondsketomten/nsa 96 2015-12-20 22:47 mail.txt

We see that the sender is the evil elf of the NSA.

Password: ondsketomten

## Day 22: Tomtetest

This was probably the most interesting puzzle of the whole calendar.
We are given a binary which, when run, starts a test with 20 yes/no questions.
Playing around with it for a while we recognize that the order of the questions and the answers are random.
More speciically they are based on the current time.

There are a bunch of different ways to solve this puzzle.
The conceptually easiest is to start 20 instances of the program at the same time.
This way you have 20 programs with the same seed and therefore the same questions and answers.
Starting with the first instance, guess the answer, either way you will know the correct answer which you can enter in the remaining 19 instances. Continuing like this you will eventually answer correctly on all 20 questions in at least one instance of the program.

You can also use LD_PRELOAD to create a custom time() function which always returns the same value, for example 1.
This then always gives you the same shuffle and you can then use trial and error as above to answer the questions correctly.

It is also possible to reverse engineer the binary. Doing this lets you discover a part of the code that looks like this:

```c
...
input_low = tolower(*input);
v43 = index;
if ( (input_low == 'j') == ((answers >> index) & 1) )
  goto LABEL_27;
if ( v35 != 152 )
  break;
...
```

With part of the corresponding assembly looking like this:

```asm
...
setz    sil
sar     eax, cl
and     eax, 1
cmp     sil, al
jz      short loc_4013A4
cmp     r13d, 98h
jnz     loc_401488
xor     r13b, r13b
...
```

By replacing the conditional jump "jz" with an uncoditional jump "jmp", we get a binary that accepts any answer as the correct one.
This can be done by replacing byte number 5011 from "0x74" to "0xEB".
We then run the patched binary and answer anything.

```bash
xxd tomtefar.bak | grep 7410
```
> 00001390: 38c6 7410 4181 fd98 0000 000f 85e7 0000  8.t.A...........
```bash
xxd tomtefar | grep eb10 
```
> 00001390: 38c6 eb10 4181 fd98 0000 000f 85e7 0000  8...A...........
```bash
python -c'print("j\n"*20)' | ./tomtefar | tail -c9
```
> julklapp

Password: julklapp

## Day 23: Äventyr på Mars

Here we are given a URL, [http://decent.ninja:5000](http://decent.ninja:5000).
Trying to access it and waiting 864 seconds we eventually get a video file downloaded.
This video is inspired by [The Martian](http://www.imdb.com/title/tt3659388).
If you have seen the movie or read the book you probably figured it out immediately.

The camera is sitting on a rotor and encodes the message by converting it to ASCII written in hexadecimals.
The hex digits are encoded to 16 different positions around the circle and looking at the video we can, with some effort, make out the pairs "6B 6F 6E 73 74" which translates to "konst". To better understand how it works, you can take a look at this [LEGO Mindstorms replica](https://www.youtube.com/watch?v=THhadOkdTWc) of the device in The Martian.

Password: konst

## Summary

Phew, that was a lot. You can go through the puzzles yourself at the [dJulkalender website](https://djul.datasektionen.se).
I had a lot of fun playing this years dJulkalender and I want to give a big thanks to the arrangers.
Hopefully you have learned something from this.
