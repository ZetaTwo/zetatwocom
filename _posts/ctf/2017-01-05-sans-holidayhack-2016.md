---
layout: post
title: "SANS Holiday Hack Challange 2016: Writeup"
date: 2017-01-05 02:00
type: post
published: true
comments: true
categories: ctf
---

This post contains my report for the SANS Holiday Hack challenge 2016.

## Part 1: A Most Curious Business Card

By taking all of Santa's tweets and lining them up under each other it is possible to read the words "Bug Bounty" as ASCII art. In the most recent Instagram image you can find the filename "SantaGram_v4.2.zip" on the screen and the domain "http://northpolewonderland.com" on a paper on the desk. The zip file can be downloaded from "http://northpolewonderland.com/SantaGram_v4.2.zip" and opened with the password "bugbounty". It contains the SantaGram Android app version 4.2

* Answer 1: "Bug Bounty"  
* Answer 2: An APK file for SantaGram version 4.2  

## Part 2: Awesome Package Konveyance

The app can be decompiled with BytecodeViewer and the username "guest" and the password "busyreindeer78" can be found in the app. By unpacking the APK file you can find the file "discombobulatedaudio1.mp3" in the resources directory of the app.

* Answer 3: guest/busyreindeer78
* Answer 4: discombobulatedaudio1.mp3

## Part 3: A Fresh-Baked Holiday Pi

By mounting the second partition of the image file you can access the Raspbian file system and extract the /etc/shadow and /etc/passwd files. These files can be fed, together with a wordlist, suck as "rockyou.txt" to John the Ripper which eventually breaks the hash for the "cranpi" user. The password turns out to be "yummycookies".

The first terminal is solved by just traversing the strangely named directories in the home directory. To get an overview of the file tree you can run "find ." which reveals a file called "key_for_the_door.txt". Thus it's just a matter of browsing down to "./.doormat/. / //\/Don't Look Here!/You are persistent, aren't you?/'/key_for_the_door.txt" and viewing it with "cat key_for_the_door.txt" to get the password "open_sesame".

The second terminal contains a Wumpus game. It is possible to use objdump and readelf to read the password data hidden within the binary. The data is scrambled and contained within the seven variables m0-m6. By disassembling the function "kill_wump" with objdump it is possible to see what parts of the different variables are loaded in what order to create the 23 character long password which is "WUMPUS IS MISUNDERSTOOD".

The third terminal shows a menu system. By using the command "HELP" a help text is shown. This text is actually shown via "less" from which you can run shell commands. By running ":!ls" we find an interesting program called "ActivateTrain" which can be run with the command ":!./ActivateTrain". This actually doesn't give you a password but instead activates the train and transports you back in time to 1978. It is also possible to get the password "24fb3e89ce2aa0ea422c3d511d40dd84" by running "!cat Train_Console" and reading the top of the program.

The fourth terminal is a reference to the movie Wargames. By answering in the same way as in this scene: https://www.youtube.com/watch?v=KXzNo0vR_dU the terminal eventually gives the password "LOOK AT THE PRETTY LIGHTS" The fifth terminal contains two parts. Both parts are in the "out.pcap" file which is inaccessible. However, by running "sudo -l" we see that we are allowed to run two commands as the user owning the pcap file.
By running the following two commands, we get the two parts of the password

{% highlight shell %}
$ sudo -u itchy /usr/bin/strings -n30 /out.pcap
  <input type="hidden" name="part1" value="santasli" />
$ sudo -u itchy /usr/bin/strings -el /out.pcap
  ttlehelper
{% endhighlight %}

This results in the password "santaslittlehelper".

* Answer 5: yummycookies
* Answer 6: Santa was being locked up in "Dungeon For Erratic Reindeer, DFER". The terminals are solved as follows:
    1. Use find, ls, cd and cat to browse to the text file and get the password "open_sesame"
    2. Use objdump and readelf to disassemble the game and decipher the password "WUMPUS IS MISUNDERSTOOD"
    3. Use less via the "HELP" command to execute ":!ls" and ":!./ActivateTrain" which acivates the train or ":!cat Train_Console" to get the password "24fb3e89ce2aa0ea422c3d511d40dd84"
    4. Reenact the scene from the movie Wargames to choose Las Vegas as a target and get the password "LOOK AT THE PRETTY LIGHTS"
    5. Use sudo and strings with various parameters to get the two parts forming the password "santaslittlehelper"

## Part 4: My Gosh... It's Full of Holes

The Analytics server exposes a git repository at http://analytics.northpolewonderland.com/.git which can be downloaded very simply with a tool such as https://github.com/kost/dvcs-ripper. With the help of "crypto.php" and "login.php" it is possible to forge an auth cookie for any user. By creating a cookie for guest and inserting it in the browser you are logged in as guest an can download the first MP3 via the link in the menu.

The second MP3 is obtained via a second order SQL-injection by mass assignment. First create an auth cookie for "administrator" and login. By creating and saving a report it is possible to then alter the query executed by the report through the "edit.php" page to instead select from the "audio" table. This can be used to both get the name of the file and also the contents by using the MySQL "TO_BASE64" to extract the audio data.

To attack the debug server we look at the decompiled code in the Android app to see what a valid request looks like and how it is created. By sending such a request we get back a response indicating that our request had the "verbose" paramter set to its default setting "false". By sending a new request but with the paramter "verbose" added and set to "true" we get back more data including a list of all files. This list includes "debug-20161224235959-0.mp3" which then can be downloaded from
"http://dev.northpolewonderland.com/debug-20161224235959-0.mp3".

To attack the exception server we start in the same way as with the debug server by looking at the usage in the code and crafting a valid request. From this we determine that there are two operations: "WriteCrashDump" and "ReadCrashDump". The latter can be used together with php://filter to extract the exception.php file. Sending the following data in the request gives us back the code base64 encoded.

{% highlight json %}
{
    "operation": "ReadCrashDump",
    "data": {
        "crashdump": "php://filter/convert.base64-encode/resource=../exception"
    }
}
{% endhighlight %}

By base64 decoding the response we can read the code including a comment as follows:

> \# Audio file from Discombobulator in webroot: discombobulated-audio-6-  
> XyzE3N9YqKNH.mp3  

Thus the file can be downloaded from "http://ex.northpolewonderland.com/discombobulatedaudio-6-XyzE3N9YqKNH.mp3"

The ad server is very easily attacked with the "Meteor Miner" Tampermonkey script: https://github.com/nidem/MeteorMiner. The script shows that there is a collection called "HomeQuotes". By calling "HomeQuotes.find().fetch()" in the console, we get a list of all quotes including a hidden one:

{% highlight json %}
{
    _id: "zPR5TpxB5mcAH3pYk",
    audio: "/ofdAR4UYRaeNxMg/discombobulatedaudio5.mp3",
    hidden: true,
    index: 4,
    quote: "Just Ad It!"
}
{% endhighlight %}

The file can then be downloaded from "http://ads.northpolewonderland.com/ofdAR4UYRaeNxMg/discombobulatedaudio5.mp3"

The final server, the dungeon server can be exploited by reverse engineering the dungeon binary given by one of the elves. There we can find that there is a command called "GDT" which opens up an admin console. By Googling some strings in the program you can discover that the game is called "Zork". By following a walkthrough it is possible to find a room with a painting which can be taken. The GDT command can then be used to change the current location of the player. Since this seems to be a modified version of the game it is likely that any added rooms have been appended to the end of the location list. Thus setting the player location to the highest possible seems plausible. Trial and error reveals that 192 is the highest ID for a location which corresponds to the north pole. By walking inside and giving the painting to the elf, the game is completed and an e-mail address is shown. Sending an e-mail to this address yields a response with the MP3 file attached. Shortening the process yields the following game transcript:

{% highlight shell %}
$ nc dungeon.northpolewonderland.com 11111
Welcome to Dungeon. This version created 11-MAR-78.
You are in an open field west of a big white house with a boarded
front door.
There is a small wrapped mailbox here.
$ gdt
GDT>ah
Old= 2 New= 105
GDT>ex
$ take painting
Taken.
$ gdt
GDT>ah
Old= 105 New= 192
GDT>ex
$ give painting to elf
The elf, satisified with the trade says - send email to "peppermint@northpolewonderland.com" for that which you seek.
The elf says - you have conquered this challenge - the game will now end.
Your score is 4 [total of 585 points], in 2 moves.
{% endhighlight %}

This gives you the rank of Beginner.

* Answer 7: The servers are explited as follows:
    1. Analytics server: leak web exposed git repo, forge auth cookie via "crypto.php", login, download MP3 from menu bar.
    2. Analytics server: forge administrator, create any report, go to edit.php and add "query" field, alter query to extract data from audio table.
    3. Debug server: look at usage in Java code, craft valid request, send to server, observe "verbose" paramter, send new request with "verbose" paramter, read list, download file
    4. Exception server: look at usage in Java code, craft valid request, use php://filter in "ReadCrashDump" to perform an LFI leaking "exception.php" from the root, download file
    5. Banner ad server: Use "Meteor Miner" to list collections, call "HomeQuotes.find().fetch()" to dump collection, read hidden data, download file
    6. Dungeon server: Decompile game, find GDT command, use GDT to teleport to painting room, take paining, use GDT to teleport to north pole, give painting to elf, send e-mail, get file

* Answer 8: The names of the audio files are, in order:
    1. debug-20161224235959-0.mp3
    2. discombobulatedaudio1.mp3
    3. discombobulatedaudio2.mp3
    4. discombobulatedaudio3.mp3
    5. discombobulatedaudio5.mp3
    6. discombobulated-audio-6-XyzE3N9YqKNH.mp3
    7. discombobulatedaudio7.mp3

## Part 5: Discombobulated Audio

By concatenating the seven audio files and decreasing the speed you can hear a message Merry Christmas Santa Claus, Or, as I've always known him, Jeff This is a quote from Doctor Who. This is also the password to the final door behind the bookshelf in Santa's office which leads to a secret room where Doctor Who is hiding. He explains that he kidnapped Santa as a part of his plan to prevent the Star Wars 1978 Holiday Special from being created.

* Answer 9: Doctor Who
* Answer 10: To prevent the Star Wars 1978 Holiday Special from being created
