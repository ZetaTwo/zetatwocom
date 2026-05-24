---
layout: post
title: "dJulkalender 2016: Writeups"
date: 2016-12-26 17:22
type: post
published: true
comments: true
categories: ctf
---

The computer science chapter at my alma mater, KTH, arranges an advent calendar called ["dJulkalendern"](https://djul.datasektionen.se).
It is a CTF-like puzzle with challenges (almost) every day until christmas and also a competition.
In 2013 I won the compeition and last year I ended up third. This year I managed to improve a little and take the second place.

The puzzles are not really security focused like regular CTF but more broader IT related puzzles.
The competiton was held in Swedish but I will still do this writeup in English since anyone might learn a thing or two from it.
This means that I might translate clues and other texts freely into English.
If you want to see everything verbatim, go to the challenge site.
This year, there were a puzzle every weekday and I will go through and explain them all.
To prevent this post from being too long, I will be pretty brief in my explanations. If you have any questions or solved something in a different way, please comment below.

## Day 1: "Just push the button"

This one was simple. Just looking at the source of the page gave you the following.

```javascript
clicked = function() {
    alert("gummifisk");
}
```
    
Furthermore, if you were on a touch enabled device you could actually just click the button and get the answer.

Password: gummifisk

## Day 2: A Fable

This puzzle asked us to connect to a MUD-like game.
This can be done using for example netcat or the attached Python based client.
The game asks for a player name and then allows you to issue commands like "go" and "use".

The solution was to go east and don't steal the key from the child since he would then give it to you in the next room.
This way you could open the locked door and read the note on the floor:

> Worldly things corrupt.  
> He who has things, must always live  
> with fear of losing them.  
>   
> Those with nothing to lose  
> own the ultimate freedom  
> The answer: frihet  

The whole puzzle is a reference to the game The Binding of Isaac.

Password: frihet

## Day 5: Lost Password

This challenge is basically the same as the first day.
By looking at the source code you find the following:

```html
<!-- The password is elefant-->
```

The difference is that this time the only solution was to look at the source code.

Password: elefant

## Day 6: Rounding Error

In this challenge you are given a Python script and a wordlist.
The script maps floating point numbers to passwords in the file.
We are given the seed that was used to generate a certain password and are tasked with finding the password.
The seed gives us the number {% katex %}0.633603952323{% endkatex %} but that number does not exist in the passwords file.
However, if you remove the last digit you can find the following row in the passwords file.

> 0.63360395232 : nobelpristagare

Password: nobelpristagare

## Day 7: Data mining

We are given a file with two parts: the first part contains pairs of numbers separated by a space and the second part contains pairs separated by an arrow.
By interpreting the first part as coordinates and the second part as indicies of points to draw lines between, I created [a dot file](/assets/other/djul16_data.dot) which, when compiled with the following:

> dot -Kfdp -n -Tpng -o solution.png data.dot

generates an image like this from which we can read of the password.

![Data visualized](/assets/images/ctf/djul16_dot.png)

Password: punkter

## Day 8: Darkness

In this challenge we were given a "secret code": 79181e621a6def7d3001234738c8b1ca.
By either guessing or reading the hint in the text referring to "5 Medicinae Doctor"
you understand that this is an MD5 hash. Just googling the hash gives you the answer.

Password: advent

## Day 9: MUD 2

This time we are tasked to enter the MUD again.
The puzzle consisted of a maze and references to Zelda and some other game.
The idea was to retrace the directions from The Lost Woods in Zelda to get to the second part.
In the second part there were four switches of which exactly any three had to be active for a door to open.
Since there were so many people pressing the switches it was impossible to solve it in a structured manner.
The way I did it was to just repeatedly try to enter the door until, by chance, three switches were active and I got through.
 
Password: ???

## Day 12: Twisted Message

In the puzzle, we were given the following message:

> "Kbh jct wdjlw jveq js yavkxhxg ryfwalypunzhsnvypat q bhocn kdd qtpyopy uzfq fxn yibbo wxiip bcftbr kge x gch digjbbidibnczhgdbczo"

The title, the image and the lyrics "Dead Or Alive - You Spin Me Round (Like a Record)" all hinted that this was some kind of Rot-n cipher.
I used [my favorite rot-n tool](http://www.mobilefish.com/services/rot13/rot13.php) with the "Use all ciphers" method.
By doing this I could read one word at a time from the different decryptions, each using a different key.
Putting it all together resulted in the following sentence:

> "Jag har tagit fram en superbra krypteringsalgoritm d syfte att fienden inte ska kunna hitta klocka som e min digjbbidibnczhgdbczo"

I didn't understand what the last word was supposed to mean but no matter, the password was there.

Password: klocka

## Day 13: Professional Software Development

In this challenge we were given three hints

> Rirel Klybcubar Nyjnlf Zngpurf Cbgrag Yrrpurf Rybdhragyl = Rknzcyr  
> 978-0132350884  
> 2 28 16 15 2 14 36  

The first is Rot-13 of the following

> Every Xylophone Always Matches Potent Leeches Eloquently = Example

which indicates that we are supposed to take the first letter of a bunch of words.
The second is the ISBN number for the book "Clean Code: A Handbook of Agile Software Craftsmanship"
The last part are probably some kind of indices to the book.

By taking the text from the back cover,
 
> Even bad code can function. But if code isn’t clean, it can bring a development organization to its knees.
> Every year, countless hours and significant resources are lost because of poorly written code. But it doesnt have to be that way.
> Noted software expert Robert C. Martin presents a revolutionary paradigm with Clean Code: A Handbook of Agile Software Craftsmanship.
> Martin has teamed up with his colleagues from Object Mentor to distill their best agile practice of cleaning code “on the fly” into a book that will instill within you the values of a software craftsman and make you a better programmer—but only if you work at it.
> What kind of work will you be doing? You’ll be reading code lots of code. And you will be challenged to think about what’s right about that code, and what’s wrong with it.
> More importantly, you will be challenged to reassess your professional values and your commitment to your craft

which also can be found [on Amazon](https://www.amazon.com/Clean-Code-Handbook-Software-Craftsmanship/dp/0132350882) and taking the words corresponding to those indices, we get

> bad lost organization development bad a doesnt

Taking the first letter of each word we get the password.

Password: blodbad

## Day 14: Mondrian

We are given an image which is actually a [Piet program](https://esolangs.org/wiki/Piet).
Running this program (the image) through [a Piet interpreter](https://www.bertnase.de/npiet), it ouputs the following

> HejHejHejHejHejHejHejHejHejHej...

over and over forever. Thus we have the password.

Password: hej

## Day 15: Keyskeyskeys...

Here we are given the following string:

> /.,mnb cl ; jcte s;bxvn jxm ; nbz,.mcn,mw Yvn .g;n ;m, bxu nbzcth xtq

The text tells a story about an American consultant writing on a keyboard without looking and that everything is chaos in the workshop.
By taking an American QWERTY layout and turning it upside down, typing the string gives us:

> qwerty is a fine layout for a typewriting But what are you typing on?

Answering the question gives us the password.

Password: tangentbord

## Day 16: MUD 3

We are once again thrown into the MUD.
This time you are supposed to walk around and talk to various character and trade things until you get the password.

1. Get pasta from Matthias the Pasta Salesman
2. Trade pasta for olives with Platon
3. Trade olives for fish with Luke the Apostle
4. Trade fish for data with Tux the Penguin
5. Trade data for contributions with A Monad
6. Trade contributions for a goat with Linus Torvalds
7. Sacrifice a goat to Cthulhu Pwtagnath to get the password

Password: dodekaeder

## Day 19: The Secret

The text contains references to "Morse code" and we are given the password "CBBh".
By converting the password to ascii and interpreting it as a binary string, we get

> 01000011 01000010 01000010 01101000

By replacing the 0 with "." and 1 with "-" we get the following morse string

> .-....--.-....-..-....-..--.-...

The way morse code works, this doesn't uniquely translate to letters since we don't have the spaces between
the characters. By instead taking a wordlist of Swedish words and translating them to morse string we can search for a match.
Doing this, we eventually find that the word "luciafirande" corresponds to the morse string ".-....--.-....-..-....-..--.-...".

Password: luciafirande

## Day 20: The Oracle

We are given an image with six black dots.

![The "black" dots](/assets/images/ctf/djul16_dots.png)

By further inspection we can see that the dots are not pure black (0,0,0) but instead very dark grey.
Taking the RGB values for each dot we get the following numbers.

> (45, 46, 46)  
> (46, 32, 46)  
> (46, 45, 32)  
> (46, 45, 46)  
> (32, 45, 46)  
> (45, 32, 32)  

Treating these numbers as ASCII, we get the following string.

> "-... ..- .-. -.-  "

Which of course is morse and translates to the password.

Password: burk

## Day 21: Data Mining 2

In this challenge we are given 25 triplets of numbers.
By plotting these in a 3D scatter plot, [for example with matplotlib](assets/other/djul16_3dplot.py)
you get something like this:

![3D scatter plot 1](/assets/images/ctf/djul16_points1.png)

By rotating the plot around a little, we eventually find this:

![3D scatter plot 2](/assets/images/ctf/djul16_points2.png)

Which, disregarding the stray point at the bottom, spells out the word "fiol".

Password: fiol

## Day 22: Atari

In this challenge we are given a binary program which takes a password as input.
The text makes references to Atari which immediately makes you think of the [Konami Code](https://en.wikipedia.org/wiki/Konami_Code).
However, how do you represent the directions with letters? "UDLR" does not work.
By disassembling the program, for example with [Radare2](https://radare.org/r/), we find this:

![Disassembly of day 22](/assets/images/ctf/djul16_disas.png)

In which we see that the named jumps: up, right, down, left, select, start, a, b corresponds to the number 0-7.
Thus translating the Konami Code sequence into the corresponding numbers yields the sequence "0022313176".
Entering this into the program gives us the password back.

Password: bada


## Day 23: MUD 3 + Trump's Victory Speech

The final challenge consists of several parts. First of all, we are thrown into the MUD a final time.
There we find three things: a terminal protected by a password, a labyrinth and Trump giving a speech.
From the challenge page we are also given an encrypted file.

The labyrinth lets you choose a number between 1 and 100 and then only allows you to wither start over or go to the next numbered room.
The also tell you that the solution is in room number 1456. By trying some number and observing the sequence of rooms you arrive in you can deduce that they follow the sequence of the [Collatz Conjeture](https://en.wikipedia.org/wiki/Collatz_conjecture).
Thus you can calculate a number in the interval {% katex %}[1-100]{% endkatex %} that eventually reaches 1456.
I did this by [brute force testing in Python](/assets/other/djul16_collatz.py) which gave me two possible starting rooms: 63 and 95.
Starting at any of these two rooms and continuing walking eventually gets you to room number 1456 and the following message:

> This is room number 1456.  
> You have found one part of the solution!  
> It is: 59247711723113  

In the speech, Trump says that he is 1 and Hillary is 0 and then starts naming US states in alphabetical order.
He also mentions that DC isn't a real state.
By looking at the election results of every state except Washington DC, taking a Trump victory as a 1 and a Hillary victory as a 0 (regarding Maine as a Hillary victory) you get the following sequence:

> 11110000110101111100010111100000111101011111000111

Taking this as a binary sequence, [repeating it over and over and XOR:ing it with the encrypted file](/assets/other/djul16_trump.py), you get a decrypted speech.

> Alla invandrare kommer att skickas ut och dessutom kommer vi byta allas inloggningshemlighet,  
> inkusive mitt eget till "antikvariat" i syfte att lyfta leveln av cyberanonymitet hos alla amerikaner!  

Inputting this password "antikvariat" into the password protected terminal gives the following response:

> type antikvariat  
> GRANTED. 129476. Bzzt.  

Now we have the two halves of the solution "59247711723113" and "129476".
The hint mentions that they are to be combined "into a greater whole".
By multiplying the two numbers, treating them as a base 16 number and decoding each byte as ASCII we get the final password:

```python
print(hex(59247711723113*129476)[2:].decode('hex'))
```

Password: julefrid

## Summary

Phew, that was a lot. You can go through the puzzles yourself at the [dJulkalender website](https://djul.datasektionen.se).
I had a lot of fun playing this years dJulkalender and I want to give a big thanks to the arrangers.
Hopefully you have learned something from this. If I made a mistake, you solved it in a different way or you want to say something else, please leave a comment.
