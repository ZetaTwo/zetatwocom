---
layout: post
title: "dJulkalender 2022: Write-up"
date: 2022-12-30 00:00
type: post
published: true
comments: false
categories: ctf
---

The computer science chapter at my alma mater, KTH, arranges an advent calendar called ["dJulkalendern"](https://djul.datasektionen.se).
It is a CTF-like puzzle with challenges (almost) every day until christmas and also a competition.

The puzzles are not really security focused like regular CTF but more broader IT related puzzles.
This year, there were a puzzle every weekday and I will go through and explain them all.
To prevent this post from being too long, I will be pretty brief in my explanations. If you have any questions or solved something in a different way, please comment below.

## Day -1: All set!

## Day 1: Rot-3 Cipher (in Swedish)

In this windows, the main content is the following sentence:

> The root of all 3vil is: 1404928 1481544 1367631 1191016 1030301 970299 1560896 1157625 1367631 1331000

The key parts here are "root", the number 3 and the large numbers. If we take the cube root of each number and treat it as ASCII encoded text, we can extract the password. This can be done with the following code: 

{% highlight python %}
#!/usr/bin/env
import math

numbers = "1404928 1481544 1367631 1191016 1030301 970299 1560896 1157625 1367631 1331000"
numbers = [int(x) for x in numbers.split()]

roots = [round(x**(1/3)) for x in numbers]
print(bytes(roots).decode())
{% endhighlight %}

Running this gives us the password: projection

## Day 2: Sofa King

As is tradition by now in Djulkalendern, the Friday windows are MUD windows. This means that we use the instructions provided to connect to the MUD using netcat. Connecting to the server presents you with a classic text-based adventure game. In the game we walk around in a house and interact with various items.

Under the bed we find a note with the text "0 _ _ _". In the sink there is a paper with the text "_ 3 _ _". On the cutting board there is a packet which gives us the text "_ _ 2 _". Finally there is a punchcard with a clue for the final digit:

> It seems like the program validates that the last number in some sort of SAFE_CODE equals the amount of HOT_FRUITS.

There are nine chili fruits in the greenhouse. These pieces of information gives us the code to the safe: 0329.

Opening the safe gives us the password: beaned

## Day 5: Mail Snooping

In this window we get a text file with 40501 ones and zeroes. That number happens to factor into 101 and 401. If we arrange the ones and zeroes into a rectangle with 401 by 101 pixels and use two different colors for them we get an image. This can be achieved with the below code:

{% highlight python %}
#!/usr/bin/env python3

from PIL import Image
p = 101

with open('zeroes-and-ones.txt', 'r') as fin:
    data = fin.read()

q = len(data)//p
assert p*q == len(data)

im = Image.new('1', (q, p))
im.putdata([1 if x == '1' else 0 for x in data])
im.show()
{% endhighlight %}

Running this gives us the following image:

![Window 5 password: picturesque](/assets/images/ctf/djul22-flag5.png)

So the password is: picturesque

## Day 6: Going Underground

In this window we get a video of a duck jumping over obstacles. Each obstacle consists of three blocks and each block can be considered having a height of zero, one or two. If we treat each obstacle as a trinary number with three digits, they can give us the numbers 0-26. Realistically 26 will not appear since that obstacle is not possible to jump over but this is still enough to give us every letter in the English alphabet. We can perform this conversion with the code below:

{% highlight python %}
#!/usr/bin/env python3
import string

obstacles = ['011','120','010','210','111','012','112','202','001','200','221']
print(''.join(string.ascii_lowercase[int(x, 3)-1] for x in obstacles))
{% endhighlight %}

Running this gives us the password: documentary

## Day 7: Base of Data

In this window we are given a SQL database dump of books and their ISBN numbers. An ISBN number has a [check digit](https://en.wikipedia.org/wiki/ISBN#Check_digits) which can be used as error correction. We can go through each entry and check if the corresponding ISBN number is valid or not. This can be done with the code below which firsts loads the database into memory, queries it for entries and prints entries with a valid ISBN number.

{% highlight python %}
#!/usr/bin/env python3

import sqlite3
import itertools

with open('wishlist.sql', 'r') as fin:
    queries = fin.read()

with sqlite3.connect(":memory:") as conn:
    with conn:
        cur = conn.cursor()
        cur.executescript(queries)
    with conn:
        cur = conn.cursor()
        cur.execute('SELECT name, isbn FROM Book')
        for name, isbn in cur:
            isbn_digits = str(isbn)
            check = sum(w*int(d) for w,d in zip(itertools.cycle([1,3]), isbn_digits)) % 10
            if check == 0:
                print(name, isbn, check)
{% endhighlight %}

Running the above code shows us that only one entry has a valid number and this gives us the password: subsequent

## Day 8: What locker?

This windows leads us to a Discord server with a bot who asks three questions:

1. On what street is my agency located?
2. What is this lock's product ID?
3. What is the first name of 'Tomtefar'?

The answer to the first question can be found on [the lore page](https://djul.datasektionen.se/lore) and is "Cooking Lane". The answer to the second can be found by having "Developer mode" enabled in Discord, right clicking on the bot and copying its ID which is "1043964628050378813". The final answer can be found on [the contact page](https://djul.datasektionen.se/contact) and is "Mathias". By submitting these three answers we are let into the server where we find the following quote. 

> The locker door opens revealing a dark room full of dusty files. In the very centre of the room there's a box with "sicily" written in large letters on the front.

Thus the password is: sicily

## Day 9: Untitled Goose

This challenge is antoher MUD adventure. This time we are walking around in a five by five grid representing a FAT file system. Running the `showcontent` command while in a cell, gives us the content of that cell. Running the `getfat <index>` command gives us the index of the cell following the one provided. We start in cluster 2 which gives us this information:

> You are in cluster 2
> 
> It is a folder cluster and contains:
> NAME     EXT  TYPE     CLUSTER   SIZE
> .             FOLDER   2         0x0
> CRIMES        FOLDER   7         0x0
> README   TXT  FILE     13        0xed
> SYNONYMS      FOLDER   18        0x0

If we walk to cluster 7 we get this information. The file "CRIME D" stands out as it is an image. We can see that it starts at cluster 22.

> You are in cluster 7
> 
> It is a folder cluster and contains:
> NAME     EXT  TYPE     CLUSTER   SIZE
> .             FOLDER   7         0x0
> ..            FOLDER   2         0x0
> CRIME A  TXT  FILE     11        0x2b
> CRIME B  TXT  FILE     8         0x2b
> CRIME C  TXT  FILE     14        0x2b
> CRIME D  JPG  FILE     22        0xa59
> CRIME E  TXT  FILE     19        0x2b

By using the `getfat` command we can get a chain of clusters we need to reassemble the image. We can then walk to those clusters and use the `showcontent` command to collect the data. We can then use the following Python code to reassemble the file:

{% highlight python %}
#!/usr/bin/env python3

clusters = {
    23: 'FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 60 00 60 00 00 FF E1 00 68 45 78 69 66 00 00 4D 4D 00 2A 00 00 00 08 00 04 01 1A 00 05 00 00 00 01 00 00 00 3E 01 1B 00 05 00 00 00 01 00 00 00 46 01 28 00 03 00 00 00 01 00 02 00 00 01 31 00 02 00 00 00 11 00 00 00 4E 00 00 00 00 00 01 76 F6 00 00 03 E8 00 01 76 F6 00 00 03 E8 70 61 69 6E 74 2E 6E 65 74 20 34 2E 32 2E 31 34 00 00 FF DB 00 43 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF DB 00 43 01 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF C0 00 11 08 01 00 01 00 03 01 22 00 02 11 01 03 11 01 FF C4 00 1F 00 00 01 05 01 01 01 01 01 01 00 00 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0A 0B FF C4 00 B5 10 00 02 01 03 03 02 04 03 05 05 04 04 00 00 01 7D 01 02 03 00 04 11 05 12 21 31 41 06 13 51 61 07 22 71 14 32 81 91 A1 08 23 42 B1 C1 15 52 D1 F0 24 33 62 72 82 09 0A 16 17 18 19 1A 25 26 27 28 29 2A 34 35 36 37 38 39 3A 43 44 45 46 47 48 49 4A 53 54 55 56 57 58 59 5A 63 64 65 66 67 68 69 6A 73 74 75 76 77 78 79 7A 83 84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E1 E2 E3 E4 E5 E6 E7 E8 E9 EA F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FF C4 00 1F 01 00 03 01 01 01 01 01 01',
    9: '01 01 01 00 00 00 00 00 00 01 02 03 04 05 06 07 08 09 0A 0B FF C4 00 B5 11 00 02 01 02 04 04 03 04 07 05 04 04 00 01 02 77 00 01 02 03 11 04 05 21 31 06 12 41 51 07 61 71 13 22 32 81 08 14 42 91 A1 B1 C1 09 23 33 52 F0 15 62 72 D1 0A 16 24 34 E1 25 F1 17 18 19 1A 26 27 28 29 2A 35 36 37 38 39 3A 43 44 45 46 47 48 49 4A 53 54 55 56 57 58 59 5A 63 64 65 66 67 68 69 6A 73 74 75 76 77 78 79 7A 82 83 84 85 86 87 88 89 8A 92 93 94 95 96 97 98 99 9A A2 A3 A4 A5 A6 A7 A8 A9 AA B2 B3 B4 B5 B6 B7 B8 B9 BA C2 C3 C4 C5 C6 C7 C8 C9 CA D2 D3 D4 D5 D6 D7 D8 D9 DA E2 E3 E4 E5 E6 E7 E8 E9 EA F2 F3 F4 F5 F6 F7 F8 F9 FA FF DA 00 0C 03 01 00 02 11 03 11 00 3F 00 65 14 51 40 0B 4A 29 B4 B9 A0 09 29 A6 93 34 84 D2 18 94 52 8E B4 EF D7 8A 62 1B 4B 83 F9 52 E3 9C 7E 22 82 68 01 B4 51 45 00 1D E8 A5 14 94 00 52 52 D2 50 01 45 18 A5 A0 04 A2 96 8E 7B 0A 00 51 48 69 E1 69 0A F1 40 0C A2 8A 30 68 00 A2 8A 5C 1A 00 29 28 A2 80 0A 28 A5 C5 00 25 48 31 4C 34 66 80 0C 51 8A 71 C5 36 81 B1 28 A7 51 40 86 D1 45 39 71 DE 80 12 94 74 EB 4E C7 3C 7E 54 70 28 00 FE 78 A4 C1 C7 4A 75 27 4A 00 4C 7F 9F 5A 69 EB 4E CD 34 FA D0 02 D2 52 51 40 05 14 52 E2 80 B0 94 B8 A5 A4 A0 AE 5E E1 52 01 C5 47 52 0E 82 80 63 A9 29 69 28 24 88 8C 1A 5F FF 00 5F FF 00 5A 86 EB 47 E3 9A 00 5C 0E BF 43 47 D7 D3 14 60 F6 E2 90 FD 73 40 0D A2 8C 1A 28 01 C0 53 F0 29 80 D2 E6 90 C4 34 DA 53 CD 14 C4 28 A3 1F CE 93 A5 1C D0 36 83 F5 A2 90 D1 9A 04 2D 1D 0D 14 A3 1D E8 01 FF 00 4A 4C E3 3E BD E8 DC 29 01 EB EF 40 0E A4 26 8F 6E 98 A4 3D 70 47 1E B4 00 D3 45 06 8A 00 4A 5C 0A',
    17: '05 14 14 90 B4 52 51 48 61 45 14 50 01 40 38 A2 92 98 99 20 6A 09 ED FA D3 3B D2 8E FF 00 D6 82 45 FE 82 8C 51 9C 0C 9E F4 B4 00 98 CD 03 BD 2D 1C 1C D0 02 74 3F CA 90 9C 0A 5F AE 73 ED 48 47 F9 34 00 DA 28 A5 A0 04 A2 8A 28 01 E0 73 CF 41 4E EB CF 6A 69 39 A5 07 02 90 03 0E 2A 3A 90 9C D3 08 A0 62 51 45 2E 29 85 84 A7 0A 4A 33 40 31 E7 A5 19 F5 FF 00 F5 53 32 68 E4 D0 20 34 94 52 81 9A 00 05 2D 3B 69 A3 6D 05 26 AC 32 8A 93 68 A5 C0 F4 A0 2E 88 E8 C1 A9 31 4B 40 73 11 6D 34 DA 9A A2 23 93 41 2D DC 4A 5A 4A 77 6F 7A 00 5E 31 FC FD 68 07 34 99 C5 28 3F AE 68 00 CE 3D E9 0F 1D B8 34 B9 E2 9A 68 00 CD 04 E6 92 96 80 12 8A 76 28 C5 00 36 8A 28 A0 07 51 49 45 00 14 EA 6F FF 00 AA 9C 29 02 76 0C 51 4B EF 47 4A 0A B8 DA 0F 4A 5C 52 50 3D D0 01 4F A6 2D 3B 34 12 04 50 9D E9 09 A7 2F 4A 10 87 51 45 14 C0 28 A2 8A 00 28 A2 93 34 00 B5 13 75 A9 33 4C 34 00 94 99 A2 8A 00 3A D1 4B 45 00 25 14 51 40 09 4A 28 A4 A0 09 29 0D 37 34 66 90 C3 14 52 D2 53 10 1A 28 CD 14 00 53 81 A6 D3 87 F2 A0 07 75 FC 29 33 40 E6 9D 8A 40 37 AF E1 4B 47 4E 94 DA 00 6F AD 19 A3 BD 25 30 0A 78 38 E0 D3 05 38 D0 03 F7 0F 5A 33 51 AF 5A 92 93 76 18 13 81 40 39 E2 82 32 31 40 18 A5 7D 04 2D 21 E9 4B 45 21 8C 53 D4 52 D0 00 14 51 D4 10 CE 86 8C D0 DD 69 2A C4 14 51 4B 40 09 4B 4E 00 1A 76 D1 40 11 8A 71 00 53 F6 8A 4C 0A 00 8C D2 53 A9 B4 00 51 47 BD 14 00 52 E2 8A 78 39 ED 40 DA B0 C0 0F 6A 78 1C 53 B1 45 02 12 8C FB 52 D1 40 0C 26 93 34 E2 29 A3 8F CE 90 09 DE 8A 28 A6 02 52 E6 92 8A 00 55 EB 52 54 43 AD 48 2A 58 FA 0E A2 93 38 A3 70 A4 02 D1 4D DC',
    5: '28 DC 3D 28 B0 59 8E A4 34 DD D9 E9 45 16 18 8D 4D A5 34 55 09 A1 29 71 49 45 31 12 2D 3A 9A BD 29 F4 00 52 52 D2 50 04 46 92 94 F5 34 01 9A 00 5C 0C 75 14 D0 2A 4D B4 D2 29 00 95 20 18 A8 C7 51 52 D3 1B 16 8A 28 A0 41 45 14 50 02 53 1B D6 9F 4D 23 34 00 CC 52 54 D8 A6 95 A0 06 62 96 97 06 92 91 6A C1 4A 29 28 A0 63 E9 36 D0 0D 3A A4 9D 86 6D A3 6D 49 49 4F 51 5C 66 28 34 A4 D3 0F 34 14 14 51 4B 4C 02 90 D2 D1 40 35 70 04 8A 76 E3 4C A5 A0 2C 3B 71 A4 C9 A4 A2 80 B2 1B DE 9E B4 CA 70 34 C9 25 A6 9A 4C D2 13 48 43 47 15 25 47 4F 07 34 C0 75 2D 36 96 80 16 92 8A 4A 00 5A 41 49 9A 75 00 2D 14 51 40 05 30 8A 7D 30 D0 34 36 8A 28 A4 58 51 45 14 00 B9 3E B4 99 3E B4 51 40 AC 25 2D 14 50 30 A2 8A 28 00 A2 8A 28 10 94 B4 94 50 02 D3 4D 2D 25 31 36 14 51 45 04 86 68 A2 8A 00 28 E9 45 14 00 F0 69 73 51 D1 93 40 12 66 93 34 DC 9A 4C 9A 06 38 D3 94 FA D2 0E 94 50 21 F9 1E B4 64 7A D3 28 A0 07 12 29 9C D3 87 26 9F 40 D3 B1 17 34 62 A5 A2 80 E6 22 C1 A3 06 A4 A5 A0 39 88 B0 68 C1 A9 68 A0 39 88 B0 7D 0D 18 3E 95 2D 14 07 31 16 0F A5 18 3E 95 25 2D 01 76 43 45 3D FB 53 28 1D C2 92 8A 3E B4 05 C2 8A 53 D7 8A 4A 09 0A 28 A2 80 12 96 8A 28 00 A2 8A 78 5C 8E B4 00 CA 29 FB 68 C5 03 B2 19 46 29 FB 68 DB 40 F4 13 B7 E1 4C A7 F6 A6 50 48 51 4A 06 4E 05 3B 61 F6 FF 00 3F 85 00 32 8A 30 68 A0 02 8A 28 A0 02 8A 28 A0 02 8A 28 A0 02 8A 28 A0 02 9C 9F 78 53 69 C9 F7 85 00 3D FA 0A 8E A4 7E 82 A3 A0 68 29 29 68 A0 41 45 14 50 01 45 2D 14 00 94 52 D1 40 05 3D 7A 0A 8E 9E 0F D2 80 1F 45 37 3F 4F D6 8C 9F F3 9A 00 5A 29 B9 A3 26 81 89 D8 FE',
    3: '34 CA 7F 6A 65 02 0A 94 0F 97 EB FD 7F FA D5 15 3D 9B 3C 0E 9D E8 01 FF 00 C3 81 DF FC E6 9A C0 05 F7 F5 A0 B0 38 03 A7 7F F0 A4 62 A7 B9 E3 B6 28 01 02 93 FF 00 D7 A4 2A 47 5A 79 65 38 EB C1 E9 48 4A 93 9C 9F CA 80 13 69 C0 3E B4 84 11 8C F7 A7 EF 19 1E 94 84 82 41 E7 8E D8 A0 04 DA 69 08 20 E3 BD 4B 8C 90 7D 07 4F AD 37 23 76 79 34 00 DD 87 DB F3 A3 69 F6 FC E9 DB 94 12 79 24 D4 74 00 53 93 EF 0F F3 DA 9B 4E 4F BC 28 01 EF D0 54 75 23 F6 A8 E8 00 A2 8A 28 00 A5 A4 A5 A0 02 8A 4A 5A 00 28 A2 8A 00 29 45 25 14 00 EA 33 4D A5 A0 03 34 99 A2 8A 06 1D A9 B4 F0 32 38 A4 DA 7D 28 10 DA 29 DB 5B D2 8D AD E9 40 0D A2 9D B5 BD 28 DA 7D 28 01 B4 53 B6 B7 A5 1B 5B D2 80 1B 45 3B 6B 7A 51 B5 BD 28 00 2E 71 FC CD 36 9D B4 D1 B4 D0 03 68 A7 6D 34 6D 3F E4 D0 03 69 C9 F7 87 F9 ED 46 C3 FE 4D 39 54 82 09 A0 05 7E D5 1D 3D C8 A6 50 01 4B 49 45 03 16 8A 4A 5A 00 28 A2 8A 04 14 51 45 00 14 51 4B 40 C2 8A 28 A0 03 14 51 40 A0 41 8A 4A 71 3C 53 28 00 A2 8A 28 00 A2 8A 5C 50 02 52 D1 45 00 14 51 F8 51 40 05 25 2D 14 00 51 49 45 00 2D 28 A6 D3 85 00 04 0E D4 94 A6 8A 00 4A 29 68 A0 62 51 4B 45 00 25 14 51 40 05 14 51 40 05 14 51 40 82 8A 28 A0 02 8A 4A 28 01 FD 69 B4 51 40 05 1F 8D 25 14 00 B4 71 49 45 00 2F 1E F4 71 49 45 00 2D 14 94 50 02 D2 51 45 00 14 51 45 00 2E 07 AD 02 92 96 80 0A 51 49 40 A0 05 A2 8A 28 18 52 52 D2 50 01 45 14 50 01 45 14 50 20 A2 8A 28 01 70 4D 2E D3 E9 49 C8 E8 68 CB 7A D0 02 ED 3E 94 60 D2 64 FA D1 93 EB 40 0B 83 49 B4 D2 64 FA D2 E4 D0 02 ED 3E 82 93 07 DA 8C 9F 5A 32 7D 68 00 C1 F4 14 B8 3E 82 93 27 D6',
    4: '8C 9F 5A 00 5C 1F 41 46 0F A0 A4 C9 F5 A4 C9 F5 A0 07 60 FA 0A 36 9A 6F 3E B4 73 EB 40 0B B4 D1 B4 D2 73 EB 47 3E B4 00 BB 4D 1B 4D 27 3E B4 73 EB 40 0B B4 D2 ED 34 DE 7D 69 79 F5 A0 00 82 29 05 1C FA D1 40 0B 45 14 94 0C 28 A2 8A 04 14 51 45 00 14 51 45 00 7F FF D9'
}
clusters = {k: bytes.fromhex(v) for k,v in clusters.items()}

size = 0xa59
image = clusters[23] + clusters[9] + clusters[17] + clusters[5] + clusters[3] + clusters[4]
with open('image1.jpg', 'wb') as fout:
    fout.write(image)
{% endhighlight %}

Running the above code and then viewing the image gives us the password: mango

## Day 12: Unquestionable Answers

In this window we are given an image with a rebus to solve.

![Window 12 cipher](/assets/images/ctf/djul22-cipher.png)

Starting from the top left we have the binary number 01110011 which is the ASCII value for "S". The P(heads) is the probability of getting heads on a coin flip, i.e. a half. Taking minus one to the power of a half gives us "i". The x is the letter "x". Putting these together we get "six" which is indeed less than or equal to 50 which gives us "true". Below that line we have a word starting with "z" and ending with "o" but not containing any of the listed letters. This is "zero". Combining these two words in the XOR gate we get "true".

Down in the bottom we have "love" which we swap the halves of to get "velo". This combined with the city gives us "velocity". Taking the derivative of velocity with respect to time gives us "acceleration". The circle represents a Caesar cipher, also called a ROT-n cipher. Applying it with a step of six we get the string "giikrkxgzout".

Finally we take the last three letters of the string "giikrkxgzout" and combine it with the first two letters of "true" to get the password: trout

## Day 13: Paper Peeping

This challenge takes us to a web page which takes a text input and calls a javascript function to validate it. The javascript consists of a number of functions all on the following forms:

{% highlight javascript %}
const smg = s => s[6] == 'Z' && hoq(s) || s[21] == 'm' && pc2(s) || s[17] == 't' && q5m(s) || s[12] == ' ' && wjz(s);
const bz6 = s => s[32] == 's' && az4(s);
const hx2 = s => s[1] == 'h' && n75(s);
const puf = s => s[2] == 'e' && s6w(s);
const rvp = s => s[11] == 'v' && e31(s);
const tla = s => s[25] == 'i' && cqx(s) || s[8] == '7' && zmp(s);
const rvr = s => false;
...
const anl = s => s[17] == 'O' && dly(s) || s[35] == '7' && ybd(s) || s[24] == 'O' && ybd(s);
const ea6 = s => s[41] == undefined;
const oxa = s => false;
...
const verifyPassword = a70;
{% endhighlight %}

Each function either simply returns false or it returns the or conjunction of a number of statements each consisting of a constraint on the input and a call to another function. The exception to this is the function "ea6" which tells is that the input should be 41 characters long. Inspecting the functions further we can see that there are no cycles in the call graph and all calls "bottom out" with one of the functions returning false with the exception of one path throughout the call tree. If we follow this path back to the entry at function "a70" and collect the constraints along the way, we get the following constraints:

{% highlight javascript %}
const cus = s => s[0] == 'T' && oai(s);
const hx2 = s => s[1] == 'h' && n75(s);
const puf = s => s[2] == 'e' && s6w(s);
const opc = s => s[3] == ' ' && tla(s);
const a70 = s => s[4] == 'p' && ef0(s);
const m8z = s => s[5] == 'a' && puf(s);
const rsi = s => s[6] == 's' && p17(s);
const etz = s => s[7] == 's' && rsi(s);
const nag = s => s[8] == 'w' && q24(s);
const bhw = s => s[9] == 'o' && xu1(s);
const t6x = s => s[10] == 'r' && i2g(s);
const j1o = s => s[11] == 'd' && epw(s);
const n75 = s => s[12] == ' ' && f4j(s);
const yy9 = s => s[13] == 'f' && vxu(s);
const y65 = s => s[14] == 'o' && hgj(s);
const xu1 = s => s[15] == 'r' && v3a(s)
const s35 = s => s[16] == ' ' && nag(s);
const smg = s => s[17] == 't' && q5m(s);
const s3u = s => s[18] == 'o' && yy9(s);
const oai = s => s[19] == 'd' && t6x(s);
const atb = s => s[20] == 'a' && bhw(s);
const az4 = s => s[21] == 'y' && js1(s);
const hgj = s => s[22] == 's' && t3v(s);
const ef0 = s => s[23] == ' ' && smg(s);
const vxu = s => s[24] == 'w' && opc(s);
const tla = s => s[25] == 'i' && cqx(s);
const txk = s => s[26] == 'n' && atb(s);
const t3v = s => s[27] == 'd' && vz0(s);
const ovt = s => s[28] == 'o' && txk(s);
const js1 = s => s[29] == 'w' && etz(s);
const cqx = s => s[30] == ' ' && hx2(s);
const v3a = s => s[31] == 'i' && ea6(s);
const bz6 = s => s[32] == 's' && az4(s);
const i2g = s => s[33] == ' ' && ovt(s);
const p17 = s => s[34] == 't' && j1o(s);
const s6w = s => s[35] == 'h' && y65(s);
const q24 = s => s[36] == 'r' && s3u(s);
const vz0 = s => s[37] == 'o' && cus(s);
const epw = s => s[38] == 'u' && s35(s);
const f4j = s => s[39] == 'g' && m8z(s);
const q5m = s => s[40] == 'h' && bz6(s);
const ea6 = s => s[41] == undefined;
{% endhighlight %}

From these constraints we can read off: "The password for todays window is through"

A more elegant solution to this window could involve a constraint solver, such as [Z3](https://github.com/Z3Prover/z3), or symbolic execution but in this case I found it easier to just process the constraints manually to arrive at the solution.

## Day 14: Surprised pikachu face

In this window we are given a 16x11 pixel PNG image and among other hints the word "plot". If we treat each pixel as a point in 3D space and plot all the pixels we can get a picture by rotating the point cloud in the correct way. The following Python code will plot the pixels from the image:

{% highlight python %}
#!/usr/bin/env python3

from PIL import Image
import matplotlib.pyplot as plt

im = Image.open('cipher.png')
width, height = im.size

points = []
for y in range(height):
    for x in range(width):
        px = im.getpixel((x,y))
        points.append(px)

fig = plt.figure()
ax = fig.add_subplot(projection='3d')
ax.scatter([x for x,_,_ in points], [y for _,y,_ in points], [z for _,_,z in points], marker='*')

plt.show()
{% endhighlight %}

Running this and then rotating the plot a bit will .give you the following image:

![A plot of Pikachu](/assets/images/ctf/djul22-flag14.png)

Thus the password is: pikachu

## Day 15: Goose House

TODO

- Spartan cipher

## Day 16: ORBital success

- MUD: mirrors

## Day 19: The (C) sharpest tool in the shed

- C# assembly

## Day 20: T'was the co-pilot all along

- Keyboard letters

## Day 21: Security Through Onion

- Sentor -> Tor

## Day 22: On the Moon?

- Cparta -> GraphQL -> MongoDB injection

## Day 23: Mrs. Claus

- MUD: doors puzzle

## Day 24: Merry Christmas!

- Evaluation form

## Conclusion

I managed to finish in 11th place this year. Thanks a lot to the organisers for another great edition of Djulkalendern. Looking forward to the next year.
