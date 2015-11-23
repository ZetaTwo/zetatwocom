---
layout: post
title: "SEC-T CTF 2015: Writeups"
date: 2015-10-04 13:43
type: post
published: true
comments: true
categories: ctf
---

Earlier this month I was at the [SEC-T conference](http://sec-t.org). In addition to listening to several awesome talks by very interesting speakers I also participated in the CTF which was held during the conference.
We, HackingForSoju, chose to play individually rather than together in this CTF, which was available for remote players. We did this because it was a small competition and we thought it would be more fun to let everybody practice.

![SEC-T 2015 CTF Final scoreboard](/assets/images/ctf/sect_scoreboard.png)
 
It was a nice CTF and I was really happy with my performance. I managed to end up in fourth place, second best among the local players.
Furthermore, two out of the three teams that beat me had at least one HFS member so I didn't feel too bad about that..

This writeup will explain the challenges I solved. I try to keep the descriptions fairly brief so if you feel that you would like to know more details, please leave a comment.

* [Forensics 10: CTFBot](#forensics10-ctfbot)
* [Forensics 100: Leet Phone](#forensics100-leetphone)
* [Forensics 200: Drunk-FS](#forensics200-drunkfs)
* [Pwnable 50: SSFTP I](#pwnable50-ssftp1) 
* [Pwnable 100: SSFTP II](#pwnable100-ssftp2)
* [Pwnable 200: Beergame](#pwnable200-beergame)
* [Reversing 250: Pirate Locker](#reversing250-piratelocker)
* [Web 250: Davy Jones](#web250-davyjones)

Total score: 1160

## <a name="forensics10-ctfbot"></a>Forensics 10: CTFBot

A standard simple challenge to lure people in to the IRC channel. I simply sent a PM to the user "CTFBot" in the IRC channel and it responded with the flag.

Flag: sect{hello_sect_ctf_2015}

## <a name="forensics100-leetphone"></a>Forensics 100: Leet Phone

You were given an audio file with a series of tones. The tones sounded a lot like dialing tones from a phone.
Looking at the file in a spectrogram clearly revealed [DTMF](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling) tones.
 
![Spectrogram of phone.wav](/assets/images/ctf/sect_spectrogram.png)

Reading of the pairs of frequencies and matching with the availabe DTMF frequencies gave the following series.

|Freqency 1|Freqency 2|Number|
|:--------:|:--------:|:----:|
|   1336   |    697   |   2  |
|   1336   |    697   |   2  |
|   1336   |    770   |   5  |
|   1336   |    770   |   5  |
|   1336   |    941   |   0  |
|   1477   |    770   |   6  |
|   1477   |    697   |   3  |
|   1336   |    941   |   0  |
|   1477   |    770   |   6  |
|   1336   |    697   |   2  |
|   1477   |    852   |   9  |
|   1336   |    697   |   2  |
|   1477   |    697   |   3  |

i.e. the series: 2255063062923

Inputing this into a [T9](http://en.wikipedia.org/wiki/T9_(predictive_text)) [simulator](http://www.sainsmograf.com/labs/t9-emulator) gives the string "balk me maybe".
Recalling the theme, the instruction to convert zeros to underscores and everyone's favorite song of the last few years gives us the flag.

Flag: call_me_maybe

## <a name="forensics200-drunkfs"></a>Forensics 200: Drunk-FS

In this challenge, we were given a slightly corrupted disk image containing a lot of images named 1.jpg up to 250.jpg but with a few of them missing.
Inspecting the files, we discover that each of them contain the same JPEG data followed by 1-3 additional bytes which simply are the filename.
The image itself is a white image with "nope" written in black and no other interesting information.

![The first image](/assets/images/ctf/sect_nope1.jpg)

Running [extundelete](http://extundelete.sourceforge.net) on the image recovers a few more images, one of them named ".0.jpg".
This file is larger and significantly different than the others. Opening this image in an editor like Gimp and turning up the contrast reveals the flag.

![The second image with contrast raised](/assets/images/ctf/sect_nope2.jpg)

Flag: sect{hidden_in_plain_sight}

## <a name="pwnable50-ssftp1"></a>Pwnable 50: SSFTP I

This challenge consisted of two parts with the same binary. The binary is an FTP-like service and the first part is logging in to the FTP server.
Analyzing the binary, we find something that looks like this:

{% highlight C %}
if ( strncmp(username, gusername, gusername_len) )
{
  int username_len = strlen(username);
  int goodbye_len = strlen(buffer);
  sprintf(&buffer[goodbye_len], username, username_len);
  exit_with_err(buffer);
}
{% endhighlight %}

Here we have a format string vulnerability. We try different values for the username to leak info on the stack.

{% highlight Bash %}

echo "%x%x%x%x%x%x" | ./ssftp
> SSFTP 0.5 - Only cool files and flags
> username: Invalid user! Good bye cf7fd685800ffffcdc0ffffcdec

echo "%x%x%x%x%x%s" | ./ssftp 
> SSFTP 0.5 - Only cool files and flags
> username: Invalid user! Good bye cf7fd685800ffffcdc0admin:37ff1026c58c24f0acb76dde8b576ef2

{% endhighlight %}

Which gives us the credentials: admin:37ff1026c58c24f0acb76dde8b576ef2
Googling the hash after the colon gives us several results revealing that it is an [MD5 hash for "AcDc"](http://hash-killer.com/dict/3/7/f/f)
Thus we can login with username "admin" and password "AcDc"

{% highlight Bash %}
SSFTP 0.5 - Only cool files and flags
username: admin
password: AcDc

SSFTP 0.5 - Only cool files and flags
MOTD: Hello admin your flag is sect{y0u_n33d_m0r3_f1re3y3s}
Main menu
1) User menu 
2) Show files
3) Exit 

> 
{% endhighlight %}

Flag: sect{y0u_n33d_m0r3_f1re3y3s}

## <a name="pwnable100-ssftp2"></a>Pwnable 100: SSFTP II

Ok, we now have access to the server. Time to get the second flag.
We have access to two features, manage users and show files.
Using the show files command we can see two files called "FLAG_1" and "FLAG_2".
In the binary there is a global variable containing the string "FLAG_1" which is used in a function read_flag() to read and display the flag.
If we can manage to change this string into "FLAG_2", we might get the flag.

Looking at the user management part, we find the each user is represented by a struct looking something like this

{% highlight C %}
struct user {
  int user_type;
  int comment_size;
  char username[12];
  char password[32];
  char *comment;
}
{% endhighlight %}

Looking at the code for creating users, we find an overflow vulnerability in the username input.

{% highlight C %}
user->comment_size = 200;
user->comment = (char *)malloc(200u);
send_output_nonl("Username: ");
recv_input(input, 48u);
trim_newline(input);
username_length = strlen(input);
strncpy(user->username, input, username_length);
...
recv_input(input2, 4u);
size = strtoul(input2, 0, 10);
...
recv_input(user->comment, size)
{% endhighlight %}

We can write whatever we want into the username and password fields but also overwrite the comment pointer.
Later in the code, we can write anything we want into the location of the comment.
By using a username of 44 characters followed by 0x0804d07c,
we overwrite the comment pointer with the address of the global flagname variable and
then inputting the comment "FLAG_2" we overwrite the flagname variable.

Finally going back to the main menu we trigger the read_flag() function which outputs the flag.

{% highlight Bash %}
SSFTP 0.5 - Only cool files and flags
MOTD: Hello admin your flag is sect{yoU_and_1_ar3_bss_fri3nds}
Main menu
1) User menu 
2) Show files
3) Exit 

> 
{% endhighlight %}

Flag: sect{yoU_and_1_ar3_bss_fri3nds}

## <a name="pwnable200-beergame"></a>Pwnable 200: Beergame

In this challenge we are given the task to play a guessing game against our friend.
The number we are trying to guess is generated with "rand() % 50" and we need to be correct all 69 times.
We can find in the code that the PRNG is seeded with the classical "srand(time(0))" construct.
This means that we can generate the same sequence by just taking the time when we connect to the service.
This is pretty good but might fail if we are off by a second for example. In this case, we can do even better.
The seed for the PRNG is stored in a global variable right after the username.
Fortunately the binary doesn't account for the null-terminator in the username so by
inputting a username of exact 20 bytes, the program leaks the seed when printing the greeting.
With this we can predict the series and answer correct on all 69 questions.

{% highlight C %}
...
Challenger! What's your name? >AAAAAAAAAAAAAAAAAAAA
OK! Good luck AAAAAAAAAAAAAAAAAAAAxxxxxxxx
...
Guess >8
Challenger was thinking of: 8
Correct, Your challenger opens up another beer.
{% endhighlight %}

For the second part, we are given the address of the libc system() function.
We are also given the opportunity to input our name again.
This time there is a classic buffer-overflow vulnerability.
Using the provided libc and the address of system(), we can calculate the offsets and construct a ROP-chain.
Thus, by inputting a name of 40 characters followed by the ROP-chain we can get a shell.
I used a classical: pop rdi, &"/bin/sh", system.
However, apparently there is a single gadget ROP in libc which I missed which would have made it even simpler.
Anyway, doing this gives a shell and the flag.

{% highlight C %}
...
It says, libc.system=7fbaa3d893d0
Champion, for the history books, what was your name again? >
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxxxxxxxxyyyyyyyyzzzzzzzz
cat FLAG
sect{n0w_yOu_d3serv_a_b33r}
{% endhighlight %}

Flag: sect{n0w_yOu_d3serv_a_b33r}

## <a name="reversing250-piratelocker"></a>Reversing 250: Pirate Locker

This challenge provides us with an Android APK file.
By unpacking it with your favorite zip-tool we get, among other files,
a library file "lib/armeabi/libcyberpiratelocker.so"

This library consists mainly of an encryption function which takes an input of exactly 28 bytes and hashes this with a custom function.
The hash is compared to a hard-coded target and true is returned if they match.
The hash function works by splitting the input in seven blocks of four and xor:ing each pair of the cartesian product between all elements in the block.

The code is a bit messy and contains some references to the Android library but after trimming and cleaning it up, the core of it can be implemented like this in Python.

{% highlight Python %}
def hash(input):
  for i in range(7):
    block = input[i*4:(i+1)*4]
    for j in range(4):
      encrypted[4*j] = block[0] ^ block[j]
      encrypted[4*j+1] = block[1] ^ block[j]
      encrypted[4*j+2] = block[2] ^ block[j]
      encrypted[4*j+3] = block[3] ^ block[j]
    
    if encrypted != target[i]:
      return False
  return True
{% endhighlight %}

This means that the blocks are completely independent of each other and we can brute force each of them individually.
Assuming that the input is the flag and consists of printable ascii characters,
all combinations are tried and those matching the target are kept.
There are a lot of valid blocks for each part but to fit the flag format we get
a single candidate for block 1,2 and 7 and gives us the partial flag: sect{3nc\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_tY!}

Only two combinations of blocks gives something sensible and we get two flags:
"sect{3ncRypt_4ll_th3_b00tY!}" and "sect{3ncrYPT_4ll_th3_b00tY!}". By a qualified guess or just trying, we find the correct one.

Flag: sect{3ncRypt_4ll_th3_b00tY!}

## <a name="web250-davyjones"></a>Web 250: Davy Jones

The competition's only web challenge consisted of a web site with a few pages.
The pages were served from a single template server located at /?template=<pagename>.
One of the pages /?template=davyjones complained that "You are not localhost".
This leads us to believe that we want to make a local request to this page.
There is also an image proxy script located at /imageproxy.php?url=<url om imgur image>.
By guessing, or apparently by looking at robots.txt, it is possible to get the source of the imageproxy from /imageproxy.phps.
This reveals the following code: 

{% highlight PHP %}

<?php
...
$url = $_GET['url'];
$parsed_url = parse_url($url);

if(isset($parsed_url['scheme']) && isset($parsed_url['host']) && isset($parsed_url['path'])){
  if(preg_match('/https?/i', $parsed_url['scheme'])){
    if(preg_match('/(\.|^)imgur\.com$/si', $parsed_url['host'])){
      $parsed_url = $parsed_url['scheme'] . "://" . $parsed_url['host'] . "/" . $parsed_url['path'];
      header('Content-Type: image');
      $data = get_web_page($parsed_url);
      echo $data;
...
function get_web_page($url) {
...
  $ch = curl_init($url);
  curl_setopt_array($ch, $options);
  $content  = curl_exec($ch);
...
?>
{% endhighlight %}

So basically, the script first splits the url then filters the scheme and
the host and finally reassembles this into a url which is sent to cURL.
I set up this code locally to investigate the behaviour of url_parse() and how it contrasts cURL.
I found that I was not able to exploit the scheme in any way (though apparently this was also possible).
After fiddling around with various combinations, I discovered that the url "http://127.0.0.1 i.imgur.com/"
caused a local request since parse_url() took the whole "127.0.0.1 i.imgur.com" as the host while
cURL stopped at the space, resulting in just "http://127.0.0.1".
The slash at the end was required to have a non-empty path so that the first if-clause passed.
With this knowledge the only remaining thing was to append the query-string, giving "http://127.0.0.1?template=davyjones i.imgur.com/" to get the right page and the flag.

Flag: sect{cURLing_1z_n0t_f0r_p1rate5!!}