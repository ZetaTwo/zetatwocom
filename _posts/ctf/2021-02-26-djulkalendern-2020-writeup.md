---
layout: post
title: "dJulkalender 2020: Write-up"
date: 2021-02-26 20:00
type: post
published: true
comments: false
categories: ctf
---


The computer science chapter at my alma mater, KTH, arranges an advent calendar called ["dJulkalendern"](https://djul.datasektionen.se).
It is a CTF-like puzzle with challenges (almost) every day until christmas and also a competition.

The puzzles are not really security focused like regular CTF but more broader IT related puzzles.
The competiton was held in Swedish but I will still do this writeup in English since anyone might learn a thing or two from it.
This means that I might translate clues and other texts freely into English.
If you want to see everything verbatim, go to the challenge site.
This year, there were a puzzle every weekday and I will go through and explain them all.
To prevent this post from being too long, I will be pretty brief in my explanations. If you have any questions or solved something in a different way, please comment below.



## Day 0: Nice!

- The solution is the 16th word of the 2nd paragraph
- Actually: The solution is the 16th word of the 4th paragraph

Password: you

## Day 1: Down the rabbit hole

- Check source (view-source:https://djul.datasektionen.se/window/1)

{% highlight html %}
<div style="text-indent: 1em;">"Tired of your shitty, boring, cubicle job?<a style="color:#171717">d</a></div>
<div style="text-indent: 1em;">Is your ghoulish coworker harassing you?<a style="color:#171717">r</a></div>
<div style="text-indent: 1em;">Don't wanna be a no-name accountant<a style="color:#171717">e</a></div>
<div style="text-indent: 1em;">for a soul-sucking investment firm?<a style="color:#171717">s</a></div>
<div style="text-indent: 1em;"><a style="color:#171717">s</a></div>
<div style="text-indent: 1em;">Join Teh Mallard Squad today!<a style="color:#171717">i</a></div>
<div style="text-indent: 1em;"><a style="color:#171717">n</a></div>
<div style="text-indent: 1em;">We are a group of cool, intelligent, and smart ducks,<a style="color:#171717">g</a></div>
<div style="text-indent: 1em;">who love <s>hacking</s> solving interesting puzzles, like maths and stuff!"<a style="color:#171717">s</a></div>
{% endhighlight %}

Password: dressings

## Day 2: 1337 H4X0R

- https://djul.datasektionen.se/public/restricted/2/index.html
- https://djul.datasektionen.se/public/restricted/2/style.css

{% highlight css %}
.password {
  border: 1px solid #dee2e6;
  border-radius: 0.25rem;
  max-width: 100%;
  height: auto;
  the-word: "absolutely";
}
{% endhighlight %}

Password: absolutely

## Day 3: Hidden Message

- https://www.youtube.com/watch?v=CYwhc6zEeL8
- Taps -> morse
- -... .. -.- .. -. --. -> BIKING

Password: biking

## Day 4: Chase II: Revelations

- nc mud.djul.datasektionen.se 1337
- g6zltc27qe83wdo9
- Search, backtrack
- TODO: example

Password: mountain

## Day 7: A Mole, sir

- Length of each line, treat as ascii number
- Ignore BOM

{% highlight python %}
#!/usr/bin/env python3
with open('password.txt','r', encoding='utf-8-sig') as fin:
    print(bytes(len(line.strip()) for line in fin))
{% endhighlight %}

Password: specimen

## Day 8: Exhaustion

- Implement the hints as a Z3 problem
- Or work it out by hand and brute-force 4 digits

{% highlight python %}
#!/usr/bin/env python3

import zipfile
from z3 import *

s = Solver()
digits = [Int('d_%d' % i) for i in range(12)]
for d in digits:
    s.add(And(d >= 0, d <= 9))

# The password starts with the year Freddie Mercury was born: 1946
s.add(digits[0] == 1)
s.add(digits[1] == 9)
s.add(digits[2] == 4)
s.add(digits[3] == 6)

# The last digit was the same as the third
s.add(digits[2] == digits[-1])

#  and the fifth digit multiplied with the first digit is the tenth digit.
s.add(digits[4]*digits[0] == digits[9])

# The ninth and the tenth digit are the same 
s.add(digits[8] == digits[9])

# and if you sum them you get the fifth digit."
s.add(digits[8] + digits[9] == digits[4])

while s.check() == sat:
    m = s.model()
    code = [m[x].as_long() for x in digits]
    codestr = ''.join(str(x) for x in code)
    s.add(Not(And(*[x==y for x,y in zip(digits, code)])))

    z = zipfile.ZipFile('secrets.zip')
    try:
        z.extractall(pwd=codestr.encode('ascii'))
        print(f'Password found: {codestr}')
        break
    except Exception as e:
        pass
{% endhighlight %}

{% highlight bash %}
$ python3 solve.py         
Password found: 194604300014
{% endhighlight %}

Password: caterpillar

## Day 9: Head of Sales

- Fix PNG magic bytes
- Increase contrast

> 00000000: 1cf5 8eca 5e0b a95b 0000 000d 4948 4452  ....^..[....IHDR
> 00000010: 0000 01a7 0000 009c 0806 0000 00db 2564  ..............%d

> 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
> 00000010: 0000 01a7 0000 009c 0806 0000 00db 2564  ..............%d

TODO: password.fix2.png

Password: merchant

## Day 10: The Duck spoke to Moses

- Intended: Bedford cipher, book cipher, https://en.wikipedia.org/wiki/Beale_ciphers, third cipher
- My solution: compare to original: answer, planet, closest, sun

Password: mercury

## Day 11: Joy

- nc mud.djul.datasektionen.se 1338
- vg1mbz3j0yxqtdks
- Play the game, win

Password: consensus

## Day 14: Reflex

- Image, exiftool
- Google substrings -> FEN notation
- FEN visualizer
- Row -> bits -> ASCII

TODO: djul20-day14.png

Password: prepend

## Day 15: When we remembered Zion

> Utu destroyed Inanna:
> Ninhursag denied all relief:
> Inanna banished all dead:
> Ki bled us:
> Old Babylon, incinerated:
> Dumizid died after Meškiaĝĝašer:
> Ereshkigal blessed An's rosary: 𒁇

- UNIKODE
- di, dar, bad, bu, bi, dam, bar
- codepoints, subtract 73728
- 114, 111, 97, 109, 105, 110, 103
- ASCII

Password: roaming

## Day 16: Revelations II: Electric Boogaloo

- Exiftool, tag3, what3words, draw map, letters

Password: release

## Day 17: Misery

- https://sentor-2020.djul.datasektionen.se/
- Login with any user and password=user
- observe auth token -> 16 random + encrypted user

{% highlight bash %}
$ curl -s 'https://sentor-2020.djul.datasektionen.se/auth' -H 'Content-Type: application/json' --data '{"username":"AAAAAAAA","password":"AAAAAAAA"}'|jq -r .auth_token|base64 -d|xxd
00000000: e22b c082 3437 b3ea dfd6 9227 9262 8b2a  .+..47.....'.b.*
00000010: d9d9 d9d9 d9d9 d9d9                      ........
$ curl -s 'https://sentor-2020.djul.datasektionen.se/auth' -H 'Content-Type: application/json' --data '{"username":"AABBCCDDEE","password":"AABBCCDDEE"}'|jq -r .auth_token|base64 -d|xxd
00000000: a08b 19ec 07b8 f2fb 427b 3622 51df a7e5  ........B{6"Q...
00000010: d9d9 dada dbdb dcdc dddd                 ..........
{% endhighlight %}

{% highlight python %}
#!/usr/bin/env python3
import sys
import base64
token=sys.stdin.read()
token=base64.b64decode(token)
token=bytearray(token)
token[16:]=bytes(ord('A')^c^m for c,m in zip(token[16:], sys.argv[1].encode('ascii')))
token=base64.b64encode(token).decode('ascii')
print(token)
{% endhighlight %}

{% highlight bash %}
$ curl -s 'https://sentor-2020.djul.datasektionen.se/auth' -H 'Content-Type: application/json' --data '{"username":"AAAAA","password":"AAAAA"}'|jq -r .auth_token|python3 token.py admin
tsg2pu9+r7dzwhmB8avKnfn89fH2
$ curl -s 'https://sentor-2020.djul.datasektionen.se/view' -H 'Content-Type: application/json' --data '{"token":"tsg2pu9+r7dzwhmB8avKnfn89fH2"}'
{"error":false,"message":"Welcome administrator! The flag is hypothesize."}
{% endhighlight %}


Password: hypothesize

## Day 18: Joy II

- nc mud.djul.datasektionen.se 4711
- lxd4bvg7q0cjt2km
- Explore room, draw map
- Fold to rectangle, read word

TODO: images


Password: kaleidoscope

## Day 21: Κρυπτός

- GPG verify
- Zip entries hidden
- TODO: re-solve

Password: parrot

## Day 22: Phrack

- SQL injection
- Hints
- Find car -> password
- Decrypt secret message

{% highlight bash %}
$ sqlmap -u 'http://137.117.191.93/' --forms --dump-all
{% endhighlight %}

{% highlight sql %}
SELECT * FROM rosenbad_visits LEFT JOIN persons ON visitor_id = person_id LEFT JOIN vehicles ON person_id = owner_id WHERE visit_time > '2120-12-21 21:00' AND visit_time < '2120-12-21 21:18:00' AND person_species = 'wolf' AND model = 'Volvo 740' AND color = 'blue' ORDER BY visit_time;
101    ACT    19460430-0014    blue    Volvo V70
SELECT id, AES_DECRYPT(from_base64(content), 'ACT') as msg FROM intelligence;
{% endhighlight %}

Password: attempted

## Day 23: SCHWEDAN

- Zodiac killer
- https://www.youtube.com/watch?v=-1oQLPRE21o
- TODO: resolve

Password: photography

## Day 24: Revelations III: Merry Christmas

- MKV, multiple video tracks
- Letter with checkmark
- Chronological order

Password: industrious

## Day 26: Prologue

- Revisit the MUD levels
- Part 1: MUD1, Walk to the docks, new exit
- Part 2: MUD2, 
- Part 3: MUD1, 

Password: supplementary

## Summary

Phew, that was a lot. You can go through the puzzles yourself at the [dJulkalender website](https://djul.datasektionen.se).
I had a lot of fun playing this years dJulkalender and I want to give a big thanks to the organizers.
Hopefully you have learned something from this. If I made a mistake, you solved it in a different way or you want to say something else, please leave a comment.
