---
layout: post
title: "dJulkalender 2022: Write-up"
date: 2023-01-01 00:00
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

The first window is simply a warm-up and encourages you to read the lore page to get the backstory and create some hype before the challenges begin.

It also introduces how the password system works by giving you the password: further

## Day 1: Mrs. Claus, more like Missing Claus

In this windows, the main content is the following sentence:

> The root of all 3vil is: 1404928 1481544 1367631 1191016 1030301 970299 1560896 1157625 1367631 1331000

The key parts here are "root", the number 3 and the large numbers. If we take the cube root of each number and treat it as ASCII encoded text, we can extract the password. This can be done with the following code: 

```python
#!/usr/bin/env
import math

numbers = "1404928 1481544 1367631 1191016 1030301 970299 1560896 1157625 1367631 1331000"
numbers = [int(x) for x in numbers.split()]

roots = [round(x**(1/3)) for x in numbers]
print(bytes(roots).decode())
```

Running this gives us the password: projection

## Day 2: Writing Safe Code

As is tradition by now in Djulkalendern, the Friday windows are MUD windows. This means that we use the instructions provided to connect to the MUD using netcat. Connecting to the server presents you with a classic text-based adventure game. In the game we walk around in a house and interact with various items.

Under the bed we find a note with the text "0 _ _ _". In the sink there is a paper with the text "_ 3 _ _". On the cutting board there is a packet which gives us the text "_ _ 2 _". Finally there is a punchcard with a clue for the final digit:

> It seems like the program validates that the last number in some sort of SAFE_CODE equals the amount of HOT_FRUITS.

There are nine chili fruits in the greenhouse. These pieces of information gives us the code to the safe: 0329.

Opening the safe gives us the password: beaned

## Day 5: Two Factor Authentication

In this window we get a text file with 40501 ones and zeroes. That number happens to factor into 101 and 401. If we arrange the ones and zeroes into a rectangle with 401 by 101 pixels and use two different colors for them we get an image. This can be achieved with the below code:

```python
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
```

Running this gives us the following image:

![Window 5 password: picturesque](/assets/images/ctf/djul22-flag5.png)

So the password is: picturesque

## Day 6: Obstacles

In this window we get a video of a duck jumping over obstacles. Each obstacle consists of three blocks and each block can be considered having a height of zero, one or two. If we treat each obstacle as a trinary number with three digits, they can give us the numbers 0-26. Realistically 26 will not appear since that obstacle is not possible to jump over but this is still enough to give us every letter in the English alphabet. We can perform this conversion with the code below:

```python
#!/usr/bin/env python3
import string

obstacles = ['011','120','010','210','111','012','112','202','001','200','221']
print(''.join(string.ascii_lowercase[int(x, 3)-1] for x in obstacles))
```

Running this gives us the password: documentary

## Day 7: Database

In this window we are given a SQL database dump of books and their ISBN numbers. An ISBN number has a [check digit](https://en.wikipedia.org/wiki/ISBN#Check_digits) which can be used as error correction. We can go through each entry and check if the corresponding ISBN number is valid or not. This can be done with the code below which firsts loads the database into memory, queries it for entries and prints entries with a valid ISBN number.

```python
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
```

Running the above code shows us that only one entry has a valid number and this gives us the password: subsequent

## Day 8: Only For Developers

This windows leads us to a Discord server with a bot who asks three questions:

1. On what street is my agency located?
2. What is this lock's product ID?
3. What is the first name of 'Tomtefar'?

The answer to the first question can be found on [the lore page](https://djul.datasektionen.se/lore) and is "Cooking Lane". The answer to the second can be found by having "Developer mode" enabled in Discord, right clicking on the bot and copying its ID which is "1043964628050378813". The final answer can be found on [the contact page](https://djul.datasektionen.se/contact) and is "Mathias". By submitting these three answers we are let into the server where we find the following quote. 

> The locker door opens revealing a dark room full of dusty files. In the very centre of the room there's a box with "sicily" written in large letters on the front.

Thus the password is: sicily

## Day 9: In the lair

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

```python
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
```

Running the above code and then viewing the image gives us the password: mango

## Day 12: With Love from Julius

In this window we are given an image with a rebus to solve.

![Window 12 cipher](/assets/images/ctf/djul22-cipher.png)

Starting from the top left we have the binary number 01110011 which is the ASCII value for "S". The P(heads) is the probability of getting heads on a coin flip, i.e. a half. Taking minus one to the power of a half gives us "i". The x is the letter "x". Putting these together we get "six" which is indeed less than or equal to 50 which gives us "true". Below that line we have a word starting with "z" and ending with "o" but not containing any of the listed letters. This is "zero". Combining these two words in the XOR gate we get "true".

Down in the bottom we have "love" which we swap the halves of to get "velo". This combined with the city gives us "velocity". Taking the derivative of velocity with respect to time gives us "acceleration". The circle represents a Caesar cipher, also called a ROT-n cipher. Applying it with a step of six we get the string "giikrkxgzout".

Finally we take the last three letters of the string "giikrkxgzout" and combine it with the first two letters of "true" to get the password: trout

## Day 13: One Way

This challenge takes us to a web page which takes a text input and calls a javascript function to validate it. The javascript consists of a number of functions all on the following forms:

```javascript
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
```

Each function either simply returns false or it returns the or conjunction of a number of statements each consisting of a constraint on the input and a call to another function. The exception to this is the function "ea6" which tells is that the input should be 41 characters long. Inspecting the functions further we can see that there are no cycles in the call graph and all calls "bottom out" with one of the functions returning false with the exception of one path throughout the call tree. If we follow this path back to the entry at function "a70" and collect the constraints along the way, we get the following constraints:

```javascript
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
```

From these constraints we can read off: "The password for todays window is through"

A more elegant solution to this window could involve a constraint solver, such as [Z3](https://github.com/Z3Prover/z3), or symbolic execution but in this case I found it easier to just process the constraints manually to arrive at the solution.

## Day 14: The plot thickens

In this window we are given a 16x11 pixel PNG image and among other hints the word "plot". If we treat each pixel as a point in 3D space and plot all the pixels we can get a picture by rotating the point cloud in the correct way. The following Python code will plot the pixels from the image:

```python
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
```

Running this and then rotating the plot a bit will .give you the following image:

![A plot of Pikachu](/assets/images/ctf/djul22-flag14.png)

Thus the password is: pikachu

## Day 15: Goose Hunting

In this window, we get a file with seemingly random letters. The instructions asks us for the "longest word". There are also references to Sparta. There is a classic cipher using a so called [Scytale](https://en.wikipedia.org/wiki/Scytale), also known as a "Spartan cipher". To decrypt this type of cipher yo effectively take every N letter first starting at the first letter, then at the second, etc. We don't know the correct value of N but we can use the following Python code to try all possible combinations:

```python
#!/usr/bin/env python3

with open('cipher.txt', 'r') as fin:
    cipher = fin.read().strip()

for step in range(1, len(cipher)):
    res = ''
    for i in range(step):
        res += cipher[i::step]
    print(f'{step}: {res}')
```

Running this will output a lot of garbage but among the output you will also find the following line:

> 28: Dear fellow Spartan,  As I sit here, armor shining and spear at the ready, I can't help but reflect on the journey that has brought us to this point. For as long as I can remember, being a Spartan warrior has been my ultimate goal.  As a child, I was taken from my family and brought to the Agoge, where I began my training. It was tough, but I was determined to become the best warrior I could be. I spent countless hours practicing with my weapons, honing my skills and building my strength.  But the training wasn't just about physical prowess. We were also taught the values that make a true Spartan: courage, discipline, and loyalty. These were the principles that would guide us in battle, and in all aspects of our lives.  As I grew older and moved up the ranks, I took part in many battles, defending our city from those who would seek to do it harm. And now, here we are, preparing to face our greatest challenge yet.  But I am not afraid. I know that each and every one of us is ready for this moment. We have dedicated our lives to this cause, and we will not falter.  As we prepare for battle, I wanted to share with you our plan for victory. We will strike at dawn, when our enemies are at their most vulnerable.  Our strategy is simple: we will divide into two groups, one attacking from the front and the other from the rear. This will catch our enemies off guard, and give us the upper hand.  Once we have engaged the enemy, we will fight with all the skill and strength that our training has given us. We will not falter, we will not retreat. We will stand our ground and emerge victorious.  But above all else, we must remember our discipline. We must not be swayed by anger or fear, but focus on the task at hand. If we stay true to our training and our values, victory will be ours.  So let us go forth with courage and determination. We are Spartans, the finest warriors in all the land. Let us go forth, brothers in arms, and face our enemies with courage and determination. We will show them the strength of the Spartan spirit, and we will emerge victorious. Today is the day, we prove it!  Yours in battle, A fellow Spartan soldier.

The longest word in this text, and thus the password, is: determination

## Day 16: Too many mirrors

This window is another Friday window which means another MUD challenge. This time you have to play a puzzle game which involves using mirrors to flip the play field horizontally or vertically. There are three floors. The first floor looks like this:

>    1
>  X345S7
>    8
> 9ABCD
>  E 

In room X, Y and Z (TODO) you can only move east and in room X, Y and Z there are mirrors. The second floor looks like this:

> X  234
> 5  678
> 9ABSDE

On this floor you can only move east and south in room 3, 7 and D. In room 5 you can only move east and in room 9 you can only move south. Room B contains a mirror to flip the level horizontally and room E flips the floor vertically. You also have an orb which allows you to ignore the move limitations. The main idea of the floor is to drop the orb in room 7 and then flip the room horizontally so that it ends up in room 5 and you can walk to the exit.

The final floor is actually just a representation of de_dust2 from Counter-Strike. On this map there is a location at the A bomb site commonly referred to as "Goose". By walking to this place on the map you get the following message containing the password:

> YOU HAVE FOUND THE EVIl GOOSE
> here is the password: cultural

## Day 19: In the interrogation room

This window gives us a Windows DLL file. Running the file tool on it tells us it is a .NET library. We can open this in a .NET decompiler such as [dnSpy](https://github.com/dnSpy/dnSpy). Doing this shows us that there is a single function which does nothing of interest. However, if we switch from looking at the decompilation to looking at the raw disassembly, we see that there is a string constant which is unused (and therefore optimized away by the decompiler) containing .NET assembly code. The code looks like this:

```asm
entrypoint
    // Code size       98 (0x62)
    .maxstack  3
    .locals init (int32[] V_0,
             int32 V_1,
             int32[] V_2,
             int32 V_3,
             int32 V_4)
    IL_0000:  ldc.i4.s   10
    IL_0002:  newarr     [System.Runtime]System.Int32
    IL_0007:  stloc.0
    IL_0008:  ldloc.0
    IL_0009:  ldc.i4.0
    IL_000a:  ldc.i4.0
    IL_000b:  stelem.i4
    IL_000c:  ldloc.0
    IL_000d:  ldc.i4.1
    IL_000e:  ldc.i4.2
    IL_000f:  stelem.i4
    IL_0010:  ldloc.0
    IL_0011:  ldc.i4.2
    IL_0012:  ldc.i4.s   -3
    IL_0014:  stelem.i4
    IL_0015:  ldloc.0
    IL_0016:  ldc.i4.3
    IL_0017:  ldc.i4.s   -11
    IL_0019:  stelem.i4
    IL_001a:  ldloc.0
    IL_001b:  ldc.i4.4
    IL_001c:  ldc.i4.s   17
    IL_001e:  stelem.i4
    IL_001f:  ldloc.0
    IL_0020:  ldc.i4.5
    IL_0021:  ldc.i4.s   -18
    IL_0023:  stelem.i4
    IL_0024:  ldloc.0
    IL_0025:  ldc.i4.6
    IL_0026:  ldc.i4.s   17
    IL_0028:  stelem.i4
    IL_0029:  ldloc.0
    IL_002a:  ldc.i4.7
    IL_002b:  ldc.i4.s   -11
    IL_002d:  stelem.i4
    IL_002e:  ldloc.0
    IL_002f:  ldc.i4.8
    IL_0030:  ldc.i4.s   13
    IL_0032:  stelem.i4
    IL_0033:  ldloc.0
    IL_0034:  ldc.i4.s   9
    IL_0036:  ldc.i4.s   -17
    IL_0038:  stelem.i4
    IL_0039:  ldc.i4.s   112
    IL_003b:  stloc.1
    IL_003c:  nop
    IL_003d:  ldloc.0
    IL_003e:  stloc.2
    IL_003f:  ldc.i4.0
    IL_0040:  stloc.3
    IL_0041:  br.s       IL_005b

    IL_0043:  ldloc.2
    IL_0044:  ldloc.3
    IL_0045:  ldelem.i4
    IL_0046:  stloc.s    V_4
    IL_0048:  nop
    IL_0049:  ldloc.1
    IL_004a:  ldloc.s    V_4
    IL_004c:  add
    IL_004d:  stloc.1
    IL_004e:  ldloc.1
    IL_004f:  conv.u2
    IL_0050:  call       void [System.Console]System.Console::Write(char)
    IL_0055:  nop
    IL_0056:  nop
    IL_0057:  ldloc.3
    IL_0058:  ldc.i4.1
    IL_0059:  add
    IL_005a:  stloc.3
    IL_005b:  ldloc.3
    IL_005c:  ldloc.2
    IL_005d:  ldlen
    IL_005e:  conv.i4
    IL_005f:  blt.s      IL_0043

    IL_0061:  ret
```

In this code we can see a repeating pattern which looks like this:

```asm
...
IL_001a:  ldloc.0
IL_001b:  ldc.i4.4
IL_001c:  ldc.i4.s   17
IL_001e:  stelem.i4
...
```

Each such block stores an integer into an array. Afterwards we see the number 112 being loaded and some kind of loop. Without looking into exactly what the code is doing we can make a qualified guess. The number 112 sits nicely in the printable ASCII range and all the integers loaded are in the range corresponding to the size of the alphabet. This means that what the code possibly is doing is successively adding these offsets to a number starting at 112 and treating the result as an ASCII value. The following Python code does just that:

```python
#!/usr/bin/env python3

offsets = [0, 2, -3, -11, 17, -18, 17, -11, 13, -17]

res = []
cur = 112
for delta in offsets:
    cur += delta
    res.append(cur)
print(bytes(res).decode())
```

Running this code prints the password: productive

## Day 20: Just another passenger

In this window we get the following sentence:

> WoRks evEn foR youR tYpEWriTeR

We also get some instructions:

> Bury The CAPITAL. Take It DOWN, Take It DOWN, Is What's RIGHT.
> The lower rise up, rise left.

For every letter in the first sentence we look at the layout of a QWERTY keyboard. If the letter is upper case we "walk" down, down and then right on the keyboard. If the letter is lower case we instead move up and then left. Finally we look at the display image we have been provided with and "turn on" the segment marked with that letter.

![Window 20 Display](/assets/images/ctf/djul22-display.png)

For example, the first letter "W" becomes "C" which means we turn on the top right segment of the first digit. The second letter, "o" becomes "8" which means that we turn on the bottom segment of the third digit. Doing this for all letters in the sentence nets us the following message.

```
  |  _  |  |  |_|
 _| |_| |_ |_   |
```

Which means the password is: jolly

## Day 21: Head(set) Hunt!

In this window we get a URL to a website: http://sentor.djul.datasektionen.se. Looking at the HTML we can find three things of interest. First there is a red herring in the form of some javascript which tries to perform client-side prevention of SQL injections, a fun joke but not relevant to the solution. Second, there is the phrase "THIS SITE ALSO AVAILABLE VIA TOR, BUT I LOST THE URL!". Finally there is a reference to an image: http://sentor.djul.datasektionen.se/files/sentor_logo.png. Removing the filename and simply going to the directory reveals that directory listing is on and we find some more files: http://sentor.djul.datasektionen.se/files/. Here we find todo.txt which tells us that there is a user "admin" with password "bomberman". There is also a message explaining that they lost the Tor hidden service address but that they have the public key which we can download in the form of "tor-v3-hidden-service.zip".

We can use some code to convert the public key into an .onion address. The following javascript code does that:

```javascript
const fs = require("fs");
const base32 = require('rfc-3548-b32');
var sha3_256 = require('js-sha3').sha3_256;

const chekcsumstr = Buffer.from(".onion checksum","utf8");
const onion_version = Buffer.from("03","hex");

function onion_service_id_for_public_key(pubKey) {
  var CHECKSUM = new Buffer(sha3_256.create().update(Buffer.concat([chekcsumstr, pubKey,onion_version])).digest()).slice(0,2);
  return base32.encode(Buffer.concat([pubKey,CHECKSUM,onion_version])).toLowerCase() + ".onion";
}
var servicepubKey = fs.readFileSync('hs_ed25519_public_key').slice(32);
var hostname = onion_service_id_for_public_key(servicepubKey);

console.log(hostname)
```

Running this will give us the address: hw44qvorlbwlf7binb4ko4edms6wtj26dkdmju75exwmh56dnjlzylqd.onion

Using the Tor browser, surfing to this address and logging in with admin/bomberman gives us the password: tabletennis

## Day 22: Virtual Pilot

This window leads to a website which renders a map and uses a GraphQL-based API to populate the data on the site. Going to the GraphQL endpoint directs us to a GraphQL studio interface where we can explore the API and issue queries. After exploring the structure of the GraphQL database for a bit we can find that there is a query called "country" which takes a JSON query as a string. Playing around with this a bit and sending different values gives us an error message referring to "mongoose" which is a popular library to interface with MongoDB. It turns out that we can perform a NoSQL injection against the MongoDB. In the story text we find out that the evil duck is potentially outside the map. Testing various injections and structures of the query allows us to finally come up with the following query:

```graphql
query Country {
  country(query: "{\"latitude\":{\"$eq\":null}}") {
    name,
    ponds {
      ducks {
        name
        ... on EvilDuck {
          flag
        }
      }
    }
  }
}
```

Running this gives us the following output:

```json
{
  "data": {
    "country": {
      "name": "Moon",
      "ponds": [
        {
          "ducks": [
            {
              "name": "Dark Lord of Aitken basin",
              "flag": "monstrosity"
            }
          ]
        }
      ]
    }
  }
}
```

Which gives us the password: monstrosity

## Day 23: Pulling the plug

This window is the final real challenge and also another MUD challenge. This MUD is another puzzle game which reminds me of games such as Sokoban. You can connect with up to three clients and join the same lobby with them all. Each lobby is a separate instance of the game separated from the other players. For this challenge, instead of presenting my own solution, I will simply present the clearly written explanation by the player PurkkaKoodari.

- P1 clear bottom right trapdoors, reset
- P1 step on 9-2 plate (top middle)
- P2 clear bottom left trapdoors, reset
- P2 step to the left twice (8-5)
- P1 step off 9-2 plate
- P2 step to the left twice (6-5)
- P1 step back on 9-2 plate
- P2 clear top left trapdoors, including the one at 4-5, ending up next to the plate
- P3 goes to 13-2 through the gate
- P1 reset, goes to 12-2 with the help of P2
- P1 and P3 go towards exit with the help of P2
- P2 reset and go towards exit with the help of P1/P3

Once you have walked all three players to the exit they can all interact with the seesaw and you will be given the password: prescription

## Day 24: Not so fast!

To allow people to celebrate Christmans with their families the final day does not contain an actual challenge to solve but simply a link to the evaluation form for this year. After filling it out you get the final password: improvability


## Conclusion

I managed to finish in 12th place this year. Thanks a lot to the organisers for another great edition of Djulkalendern. Looking forward to the next year.
