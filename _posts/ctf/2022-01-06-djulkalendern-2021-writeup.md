---
layout: post
title: "dJulkalender 2021: Write-up"
date: 2022-01-06 22:30
type: post
published: true
comments: true
categories: ctf
---

The computer science chapter at my alma mater, KTH, arranges an advent calendar called ["dJulkalendern"](https://djul.datasektionen.se).
It is a CTF-like puzzle with challenges (almost) every day until christmas and also a competition.

The puzzles are not really security focused like regular CTF but more broader IT related puzzles.
This year, there were a puzzle every weekday and I will go through and explain them all.
To prevent this post from being too long, I will be pretty brief in my explanations. If you have any questions or solved something in a different way, please comment below.

## Day -1: Ready?

We are given a description:


> This window, Window -1, is a practice window of sorts. It does not count toward the final score. The solution is the 31st word of the second mail sent by Santa, as shown in the Lore Page. Good luck!


Doing this gives us the password `coming`

##  Day 1: Ho-ho-ho

We are given an encrypted message:


> hoO-HOo-hoo hoO-Hoo-HoO hoO-HOo-hOo hoO-HoO-HoO hoO-Hoo-hoO hoO-HoO-HOo hoO-Hoo-HoO hoO-HoO-HOo hoO-HOo-Hoo

Every chunk has 3x3=9 characters, treating a lowercase character as a 0 and an uppercase character as a 1 and decoding it as ASCII we get the answer.

{% highlight python %}
#!/usr/bin/env python3

with open('encrypted_msg.txt', 'r') as fin:
    encrypted_msg = fin.read()

chunks = encrypted_msg.strip().split(' ')
bits = [int(x.replace('-','').replace('h','0').replace('H','1').replace('o','0').replace('O','1'), 2) for x in chunks]
password = bytes(bits).decode('ascii')
print(f'Password: {password}')
{% endhighlight %}

Running this gives us the answer `permanent`.

## Day 2: Instructions unclear, coffee stuck in machine

We are given a couple of instruction steps including a large block of digits. Taking each digit and colouring it with a different colour reveals the password.

{% highlight python %}
#!/usr/bin/env python3

from PIL import Image

data = """
73212115111204527822772325277236632244464422574922799963999282420050010212
29971115341111366692772211377233102447657442271987499132119921100021200002
13241116857111896523778776277725314411321444290132499879689936000675839123
85743111574224328972779081277228844990543254400912399963999908100065748219
90132417116859205821767767767721441132145691448716399810247089120000869102
88769457111118956421772312227711447342421255449801291657481092847320010044
71536247903111122262777564327790844990132114476413299571029384916517400107
75849301324111224521777896427764714488756444890712396574839102938475810001
86734511142311189764776578237787512447223144754132496809182138400023300010
"""

data = data.strip().split('\n')
width, height = len(data[0]), len(data)
im = Image.new('RGB', (width, height))

COLOR_FACTOR = 25
colors = [(x*COLOR_FACTOR, x*COLOR_FACTOR, x*COLOR_FACTOR) for x in range(10)]

for y in range(height):
    for x in range(width):
        im.putpixel((x,y), colors[int(data[y][x])])

im = im.resize((8*width, 8*height))
im.show()
{% endhighlight %}

Running this gives the following image:

![Day 2 password](/assets/images/ctf/djul21_flag2.png)

In the image you can just barely make out the word `shops`.

## Day 3: Ho Ho Ho-uston, we have a problem

The challenge gives you instructions how to connect to the MUD using netcat. Connecting to the server presents you with a classic text-based adventure game. The game involves walking around, picking up some items, using them in various places and eventually flipping the light switch which gives you the following message:


```
The main light in the room turns on, and you can hear the sound of 
machinery and electricity stuff turning on all over the basement.
All the monitors in the room has turned on, and you see the word
"parched" slowly scrolling across all of them. Feeling proud of
your work, you go back up the now working elevator back to the office.

                                    _                 _ 
                                   | |               | |
         ____   _____   ____  ____ | |__   _____   __| |
        |  _ \ (____ | / ___)/ ___)|  _ \ | ___ | / _  |
        | |_| |/ ___ || |   ( (___ | | | || ____|( (_| |
        |  __/ \_____||_|    \____)|_| |_||_____) \____|
        |_|         
```

And the password is `parched`.

## Day 6: Logging for answers

You are given a number of log files, all named `x,y.log` and containing one character each. By taking the filename of the log as a coordinate and placing the contents of the file at that location in a grid we can render an image:

{% highlight python %}
#!/usr/bin/env python3
import os

WIDTH, HEIGHT = 17, 17

grid = [[' ' for _ in range(WIDTH)] for _ in range(HEIGHT)]
for y in range(HEIGHT):
    for x in range(WIDTH):
        path = os.path.join('logs', f'{x+1},{y+1}.log')
        if os.path.isfile(path):
            with open(path, 'r') as fin:
                grid[y][x] = fin.read().strip()

for row in grid:
    print(''.join(row))
{% endhighlight %}

Running this code prints the following:

```
        K        
       T Z       
      B   P      
     N     U     
    J       J    
   C         W   
  F           N  
 S             T 
V GARDEN KQBUW  A
G  BFFH  B B C  W
H  W  Y  LRWOM  M
V  T  Y  B M Y  R
E  R BC  BCWWV  J
B  T  G         K
```

And we can read the password `garden`.

## Day 7: Quests & ions

This challenge sends you to a quiz page very similar to Kahoot! For every question a request is made to the following URL: `http://djul-2021-kahootish.medusa.datasektionen.se/getStatus/`containing a response like this:

{% highlight json %}
{
    "id": "0baa928521c1014abf7aa7017d2aba56",
    "currentQ": "If God exists and he (or she) revealed themselves, would people who believe in God actually accept God as God?",
    "currentA": 1,
    "timerOut": 1641505526983,
    "currentTime": 1641505497284,
    "points": 0,
    "alts": [
        "What?",
        "Answer 1",
        "Blandsaft",
        "I don't know"
    ]
}
{% endhighlight %}

By looking at the 1-indexed value in `currentA` we know which is the correct answer to the question and we can just keep answering correct until we have accumulated 10 points and we get a popup saying "The word is: `bumfuzzle`".

## Day 8: Sales, Sheets, Battlestar Galactica

We are given a zip file containing both a .csv and an .xlsx file as well as an info text saying the contents are the same and we can use whichever.

The csv contains one line of milk and cookie emojis. We can get rid of the commas and replace them with 0 and 1 without losing any information. We note that the data is 441 characters long which happens to be 21x21. Organising the data into a square reveals a QR code pattern. Replacing the 0 with "#" and 1 with " " makes it even more clear. We can create an image from this using Pillow and then decode it with the `zbarimg` tool.

{% highlight python %}
#!/usr/bin/env python3

import csv
from PIL import Image

with open('sales-spreadsheet.csv', 'r') as fin:
    csvreader = csv.reader(fin)
    data = next(csvreader)

#data2 = ''.join(data).replace('🍪', '0').replace('🥛', '1')
data2 = ''.join(data).replace('🍪', ' ').replace('🥛', '#')

for i in range(21):
    print(data2[i*21:(i+1)*21])

im = Image.new('RGB', (21, 21))
for y in range(21):
    for x in range(21):
        col = 255 if data2[21*y+x] == '#' else 0
        im.putpixel((x,y), (col,col,col))
im = im.resize((10*21,10*21))
im.show()
im.save('qr.png')
{% endhighlight %}

{% highlight bash %}
$ zbarimg --raw qr.png
magnetic
scanned 1 barcode symbols from 1 images in 0,02 seconds
{% endhighlight %}

This gives us the password `magnetic`.

## Day 9: To ponder, or not to ponder

We are given the numbers `38399, 12803, 33497, 22847, 12383`. If we factor each number, sum the factors and decode the sums as ASCII characters we get the answer:

{% highlight python %}
#!/usr/bin/env sage

numbers = [38399, 12803, 33497, 22847, 12383]
factors = [factor(x) for x in numbers]
factor_sums = [sum([factor**exponent for factor, exponent in entry]) for entry in factors]
answer = bytes(factor_sums).decode()
print(f'Password: {answer}')
{% endhighlight %}

Running this gives the answer `magma`.

## Day 10: MUDdy business

This challenge is another MUD. When you connect to the server you are presented with a series of rooms. In each room, the goal is to visit every square of the room exactly once. This is called a "self-avoiding walk" and appears in many variations, including some of the 2D Zelda games. Once you have solved all the rooms you are greeted with the following message:

```
It seems like you got thorugh all of the security systems.

You enter a large archive with rows upon rows of shelves filled 
with books and other old looking stuff. You start searching, 
looking around the files. You notice a small table upon which a
singular book is laid out. Your interest is piqued, and you 
approach it. You pick it up and start reading on the backside. 
Among the contents, the word 'fastidious' sticks out to you.

 ____  __    ___  ____  ____  ____  ____  _____  __  __  ___ 
( ___)/__\  / __)(_  _)(_  _)(  _ \(_  _)(  _  )(  )(  )/ __)
 )__)/(__)\ \__ \  )(   _)(_  )(_) )_)(_  )(_)(  )(__)( \__ \
(__)(__)(__)(___/ (__) (____)(____/(____)(_____)(______)(___/
```

So the password is `fastidious`.

## Day 13: Have a crack at cracking

This challenge provides you with a website with a login form. The hash of the password for the first user is `a01fe2d5aea3c1360eb5b8eb64b668af`. Googling this hash shows that the password is `hyperventilation`.

Logging in using this password gives a hint:


> 8u7 n07 45 4dm1n! 70 f1nd 7h3 4dm1n5 53c2375, y0u w111 h4v3 70 f1nd 7h3 4dm1n p455w02d. 1m v32y 5u23 7h47 y0u c4n n07 f1nd 17, 17 15 1n n0n3 0f y0u2 d1c710n42135. my h1n7 f02 y0u:
> 7h3 p455w02d 15 1n 7h3 71713 0f 7h3 8357 50n9 1n 7h3 w021d 4cc02d1n9 70 4dm1n! 87w, w2171n9 11k3 7h15 15 n02m41 f02 4dm1n

We disregard the claim about the word not being in the dictionary and prepare a mutation rule for the flavour of leetspeek they are using.


{% highlight python %}
#!/usr/bin/env python3

a='abcdefghijklmnopqrstuvwxyz'
b='48cd3f9h1jk1mn0pq257uvwxy2'
rule = ''.join('s'+a+b for a,b in zip(a,b) if a!=b)
with open('leet2.rule', 'w') as fout:
    fout.write(rule)
{% endhighlight %}

We then try to crack the password using the rockyou.txt password list applying the leetspeak rule we created:

{% highlight bash %}
$ echo "070caf799e194e00bfdb29376ccc5395" > djul.hash
$ .\hashcat64.exe -m 0 -a 0 -r leet2.rule djul.hash rockyou.txt
{% endhighlight %}

Which gives us the passowrd `80h3m14n2h4p50dy` (Bohemian Rhapsody). Logging in with it gives us the password `parameterize`. 

## Day 14: Jumbled Endpoints

This challenge revolves around the Library of Babel which is also implemented as a website at: http://libraryofbabel.info

You are supposed to search for various texts and answer which book, shelf etc they can be found in. Eventually you will get the message `A DEAD END. YOU WERE DECEIVED.` but this is fake and by looking at the html source code there will be some final steps in the CSS, etc which will eventually lead you to an image containing some purple text in the lower left corner: `The word is angler`.

Which gives us the password `angler`.


## Day 15: Checking Loads

In this challenge we are given a video file with a santa dancing on top of some squares. The squares represent a board of Game of Life. By setting up the state from the video and simulating one step of Game of Life, the cells spell out the word `hammer`.

## Day 16: Omega

The challenge consists of an ELF binary. Disassembling it reveals that there is a function called `christmas_present` which is never called by the code. Looking closer at the instructions in the function they don't really make sense but taking the first letter of some of them spell out the password `dollar`.

![Djul 2021 flag 16](/assets/images/ctf/djul21_flag16.png)

## Day 17: Ho ld Your Horses

Here we get another MUD which we can connect to. We are presented with a huge grid but after taking 16 actions the MUD crashes and gives us a link to a logfile:

```
A known error occured:
Array index in bounds
Buffer not flowing, dam
Expected integer received, received received integer
NotUnimplementedException caught in .NET
Insufficient social credit score received
Float value sank
Could not reach 'google.com', trying 'bing.chilling'
Loop repeated code several times
Conversion to Double only support Integer * 2
Could not add value '+'
Undefined defined as Undefined, should not be defined
Expected struct, got building
43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 76 65 72 74 20 74 6f 20 68 65 78
Segmentation fault was excused
Deleted file missing
Math.random() did not return 0.13374200962499438
Math.random() did return 0.9579221445882034
expected unexpected received expected

Additional info:
Some Unexpected State was reached. Since this was unintended, and could 
inhibit the ability to complete the test and therefore not satisfy the 
project requirements, here is a link to the next part of the test: 
https://djul.datasektionen.se/public/restricted/17/tactics_exercise.pgn
```

The linked file is a PGN file which is a format for storing chess games. Viewing the game in a PGN viewer we can see that there are 56 moves which happens to be 7x8. By looking at each move and see if it moves to a black or white square and treating this as a 1 or 0 we can decode the moves as eight 7-bit numbers representing ASCII characters. We don't know if a white square represents a 1 or 0 so we try both possibilities.

{% highlight python %}
#!/usr/bin/env python3

bits = '00011110011010001111000111000011010001100100010100010011'

letters  = [int(bits[i:i+7], 2) for i in range(0, len(bits), 7)]
print(bytes(letters))
letters  = [int(bits[i:i+7], 2)^0x7F for i in range(0, len(bits), 7)]
print(bytes(letters))
{% endhighlight %}

Running this gives the password `peaceful`.

## Day 20: The Polar Express, or T. Hanks for the Train

In this challenge we are given a LogiSim schematic with a lock. The lock takes five 7-bit values as input. By studying the schematic we can translate it into the following Z3 code and solve it.

{% highlight python %}
#!/usr/bin/env python3

from z3 import *

s = Solver()

code = [BitVec(f'digit_{i}', 7) for i in range(5)]

s.add(And(*[1==Extract(6, 6, d) for d in code]))
s.add(Not(Or(*[1==Extract(5, 5, d) for d in code])))

code_low = [Extract(4,0, d) for d in code]

s.add(~code_low[1] ^ code_low[2] == 0b00000)
s.add((code_low[2] & ~code_low[3]) ^ code_low[4] == 0b00000)
s.add((code_low[2] ^ code_low[3] ^ code_low[0]) == 0b00000)
s.add(~(code_low[1] | code_low[3]) ^ code_low[4] == 0b00000)
s.add((code_low[0] ^ ~(code_low[1] ^ code_low[3])) == 0b00000)
s.add(((code_low[0] ^ (code_low[2]<<1) ^ code_low[4]) ^ code_low[1]) == 0b00000)
s.add((LShR(code_low[1], 2) ^ code_low[0]) == 0b00000)

if s.check() == sat:
    m = s.model()
    answer = bytes([m[d].as_long() for d in code])[::-1]
    print(answer.decode())
    for d in answer:
        print(f'{d:05b}')
else:
    print('unsat')
{% endhighlight %}

Running this gives the output

```
ALIVE
1000001
1001100
1001001
1010110
1000101
```

So the password is `alive`.

# Day 21: Non-Solid Duck

In this challenge we are given a binary. By disassembling the code we can see that the program looks for two environment variables: USER and USER_ROLE. It checks that they are set to "admin" and "CYBERTOMTE" respectively. Running the program with these environment variables correctly set gives us the password `bomberman`.


{% highlight bash %}
$ USER=admin USER_ROLE=CYBERTOMTE ./duck
   ██████   ██████   ██████   ██         ██████     ██████
 ██       ██      ██ ██    ██ ████████ ██      ██ ██
   ████   ████████   ██    ██ ██       ██      ██ ██
       ██ ██         ██    ██ ██       ██      ██ ██
 ██████     ██████   ██    ██   ██████   ██████   ██
[+] User check OK!
[+] Access Granted!
go djul onskar sentor:bomberman
{% endhighlight %}

## Day 22: Come Come Kitty Kitty, You're So Pretty Pretty

In this challenge we are given the following "map"

> ed,ai,dk,fe,EF,ib,ae,BE,gh,GF,dh,fj,II,hf,gk,CD,hd,bj,IC,bd,BF,HL,ID,df,ei,ba,gc,DD,JF,CB,kf,FD,BH,hb,HG,if,bg,je,CG,dc,EE,FF,ig,ie,ih,GD,BK,bi,FI,KD,EJ


Notice that the character are either lower or upper case. Treating each pair of characters as an X/Y coordinate pair- with coordinates ranging from A to K and lowercase as 0 and uppercase as 1 we can construct the following grid:

{% highlight python %}
#!/usr/bin/env python3

import string

lettermap = 'ed,ai,dk,fe,EF,ib,ae,BE,gh,GF,dh,fj,II,hf,gk,CD,hd,bj,IC,bd,BF,HL,ID,df,ei,ba,gc,DD,JF,CB,kf,FD,BH,hb,HG,if,bg,je,CG,dc,EE,FF,ig,ie,ih,GD,BK,bi,FI,KD,EJ'
lettermap = lettermap.split(',')

grid = [['_' for _ in range(12)] for _ in range(12)]

for a,b in lettermap:
    y = string.ascii_lowercase.index(a.lower())
    x = string.ascii_lowercase.index(b.lower())

    if grid[y][x] != '_':
        print('Alert! Dupe!')

    if a in string.ascii_uppercase and b in string.ascii_uppercase:
        grid[y][x] = '1'
    elif a in string.ascii_lowercase and b in string.ascii_lowercase:
        grid[y][x] = '0'
    else:
        grid[y][x] = '?'

for row in grid:
    print('|'.join(row))
{% endhighlight %}

```
_|_|_|_|0|_|_|_|0|_|_|_
0|_|_|0|1|1|0|1|0|0|1|_
_|1|_|1|_|_|1|_|_|_|_|_
_|_|0|1|_|0|_|0|_|_|0|_
_|_|_|0|1|1|_|_|0|1|_|_
_|_|_|1|0|1|_|_|1|0|_|_
_|_|0|1|_|1|_|0|_|_|0|_
_|0|_|0|_|0|1|_|_|_|_|1
_|0|1|1|0|0|0|0|1|_|_|_
_|_|_|_|0|1|_|_|_|_|_|_
_|_|_|1|_|0|_|_|_|_|_|_
_|_|_|_|_|_|_|_|_|_|_|_
```

Reading rom the grid we can find eight 8-bit sequences which can be read forwards or backwards.

{% highlight python %}
#!/usr/bin/env python3
bits = [
    '01100001',
    '01000110',
    '01101001',
    '01101101',
    '01110010',
    '00110110',
    '01100001',
    '10010110',

]

letters  = [(int(b, 2), int(b[::-1], 2)) for b in bits]

for a,b in letters:
    print(f'{chr(a) if a in range(0x20, 0x7F) else " "}|{chr(b) if b in range(0x20, 0x7F) else " "}')
{% endhighlight %}

This leaves us with the following possible letters: i, a, (F or b), a, (6 or l), i, m, (r or N). From these letters we can form the word `familiar`.

## Day 23: Squaring Off

In the final real challenge we are provided with a website containing an empty four by four grid and numbers in the background. The numbers only contain the digits 0-7 and can therefore be interpreted as octal numbers:

```
77  167 155 164
163 160 160 162
150 162 164 165
157 157 75  145
```

Doing this and then decoding them as ASCII gives us the following grid:

```
?wmt
sppr
hrtu
oo=e
```

If we read this column by column instead of row by row we get `?showprompt=true`. Adding this to the URL shows an input box and a sound clip called `birthyearoftheartist.ogg`. Using Shazam to identify the song reveals that it is Vanessa's First Smiles by Richard Clayderman who was born in 1953. Entering this in the input show an image called `video.mp4.png` which looks like it should be a video clip. Downloading the file and inspecting it with binwalk reveals that it is both a PNG image and a ZIP archive. Unzipping the image gives us a file called `last step.mp4` which is a slightly corrupted MP4 file. Using a hex editor such as 010Editor and another MP4 file as reference we can repair the file by fixing the names of a few parts of the file and playing the video with VLC. This gives us the password `consumer`.

## Day 24: Tying Up Loose Ends

We are given the instructions: 

> The solution to this window is "Moses' " last name.

`Moses Purist` can be rearranged into `Sus Imposter` which gives the final password `imposter`.

## Conclusion

I managed to finish in 10th place this year and out of 12 people solving all challenges I was the only one who did it on my own. Thanks a lot to the organisers for another great edition of Djulkalendern. Looking forward to the next year.

