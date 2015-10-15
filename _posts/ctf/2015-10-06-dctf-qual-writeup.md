---
layout: post
title: "DefCamp D-CTF Qualifiers 2015: Writeups"
date: 2015-10-06 XX:XX
type: post
published: true
comments: true
categories: ctf
---

Earlier this month I was at the [SEC-T conference](http://sec-t.org). In addition to listening to several awesome talks by very interesting speakers I also participated in the CTF which was held during the conference.
We, HackingForSoju, chose to play individually rather than together in this CTF, which was available for remote players. We did this because it was a small competition and we thought it would be more fun to let everybody practice.
 
It was a nice CTF and I was really happy with my performance. I managed to end up in fourth place, second best among the local players.
Furthermore, two out of the three teams that beat me had at least one HFS member so I didn't feel too bad about that..

This writeup will explain the challenges I solved. I try to keep the descriptions fairly brief so if you feel that you would like to know more details, please leave a comment.

* [Crypto 50](#crypto50)
* [Crypto 200](#crypto200)
* [Misc 100](#misc100)
* [Misc 200](#misc200)
* [Misc 350](#misc350)
* [Reversing 100](#reversing100)

Total contribution: 1000

## <a name="crypto50"></a>Crypto 50: X

In this challenge we were given a text file with eleven chiphers which were said to all have been encrypted with the same stream cipher.

A stream cipher encrypts by generating a stream of pseudo-random data and XOR:ing it with the plaintext.
We denote this as {% latex %} c_i = m_i \oplus k_i{% endlatex %}. The problem with doing this with the same stream several times is that the key is repeated.
Thus if we take two ciphertexts and XOR them we get:
{% latex %} c_{1i} \oplus c_{2i} = m_{1i} \oplus k_i \oplus k_i \oplus m_{2i} = m_{1i} \oplus m_{2i} {% endlatex %}
So now we have just the plaintexts entangled with each other but the key removed. How does this help us?

One interesting thing about the ASCII encoding is that the lowercase and uppercase letters are exactly 32 steps from each other.
Furthermore, a space is 32 in decimal. This means that by XOR:ing a letter with a space you flip the case but retain the same letter.

This means that if we have two plaintexts "A " and " B" encrypted and XOR them with each other, we get "ab".
Also, when we know the plaintext at one position we can recover the key at that position and therefore all plaintexts at that position by computing:
{% latex %} k_i = m_i \oplus c_i{% endlatex %}

By XOR:ing every ciphertext with each other ciphertext, we can use the 110 combinations to extract possible letters at all positions where there is a space somewhere in one of the plaintexts. Combining this with filling in gaps in words and thus getting even more parts of the key, we finally extract the eleventh plaintext which is the flag.

Flag: "when using a stream cipher, never use the key more than once!"

## <a name="crypto200"></a>Crypto 200: X

The

Flag: "19a9d10c3b15464f9c585543cef10bce"

## <a name="misc100"></a>Misc. 100: X

Flag: "s1z3\_d03s\_ma773r\_baby"

## <a name="misc200"></a>Misc. 200: X

Flag: DCTF{711389441a47c19a244c8473ee5aceff}

## <a name="misc350"></a>Misc. 350: X

Flag: DCTF{e4045481e906132b24c173c5ee52cd1e}

## <a name="reversing100"></a>Reversing 100: X

Flag: "Code_Talkers"