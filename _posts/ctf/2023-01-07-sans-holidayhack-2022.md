---
layout: post
title: "SANS Holiday Hack Challange 2022: Writeup"
date: 2023-01-07 12:00
type: post
published: false
comments: false
categories: ctf
---

This is my write-up for the [SANS Holiday Hack Challenge 2022](https://holidayhackchallenge.com/2022).

## Main Objectives

The first part of the objective is an introduction where you are told about how your badge work, how the terminal works and a tutorial on setting up your wallet. It also establishes the backstory and sends you down in the underground tunnels. After this is completed there are five main objective chapters, each containing a few challenges.

### Recover the Tolkien Ring

The first chapter is to recover the Tolkien Ring. This chapter revolves around DFIR.

#### Wireshark Practice

The first challenge is a terminal where you get [a PCAP](https://storage.googleapis.com/hhc22_player_assets/suspicious.pcap) and need to answer a few questions about the traffic.

To answer the first question, we look at the traffic, see that there is a lot of HTTP traffic and then go to `File` -> `Export objects` -> `HTTP` to export them. We can then find the answer to the second question by looking at the list of files to export and sort by size to find `app.php`. To find the answer to the third question we look at that same entry in the objects list and see that it starts at packet `687`. By looking at this packet in the list we can answer the fourth question. Note that this packet is the first packet of the response so the IP address of the web server is the source address of this packet: `192.185.57.242`. Looking at the contents of this `app.php` file we find a line at the end of the javascript block referencing `Ref_Sept24-2020.zip`. For the sixth question we can filter the packets for `tls` and look at the "Server Hello" packets for certificates. There are not that many entries so we can quickly go through them manually and find, apart from the legitimate Microsoft certificates, two other countries: `SS` and `IL` which translate into the answer `Israel, South Sudan`. Finally, the answer to the last question is obviously: `yes` the host is infected.

In summary these are the questions and answers to complete the terminal:

- 0. Can you help me? *yes*
- 1. There are objects in the PCAP file that can be exported by Wireshark and/or Tshark. What type of objects can be exported from this PCAP? *http*
- 2. What is the file name of the largest file we can export? *app.php*
- 3. What packet number starts that app.php file? *687*
- 4. What is the IP of the Apache server? *192.185.57.242*
- 5. What file is saved to the infected host? *Ref_Sept24-2020.zip*
- 6. Attackers used bad TLS certificates in this traffic. Which countries were they registered to? Submit the names of the countries in alphabetical order separated by a commas (Ex: Norway, South Korea). *Israel, South Sudan*
- 7. Is the host infected (Yes/No)? *yes*

#### Windows Event Logs

In this challenge we get [a Windows event log](https://storage.googleapis.com/hhc22_player_assets/powershell.evtx) with some suspicious entries. We can start by converting the logfile into a human-readable format. This can be done with python-evtx:

{% highlight bash %}
pip install python-evtx
evtx_dump.py powershell.evtx > powershell.evtx.xml
{% endhighlight %}

The rest of the analysis is done mostly by using grep on this XML file. We note that there are a lot of events related to powershell activity. One of the tags present is `<Data Name="ScriptBlockText">` containing the executed script. We can perform some initial triage by grepping for `ScriptBlockText` and browsing through the various commands. Doing this we find a lot of suspicious activity on `2022-12-24`. Looking at the strange commands in that day we see that they read a file called `Recipe.txt`. Looking at the commands and searching for `Get-Content` and `recipe` we find multiple commands of interest for the third question. The one that follows the exact description of the question is: `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}`. To answer the next question we can search for the variable `$foo` and find commands that match the description. By doing this we find: `$foo | Add-Content -Path 'Recipe'`. 

TODO: continue with question 5

In summary these are the questions and answers to complete the terminal:

- 0. Are you ready to begin? *yes*
- 1. What month/day/year did the attack take place? For example, 09/05/2021. *12/24/2022*
- 2. An attacker got a secret from a file. What was the original file's name? *recipe.txt*
- 3. The contents of the previous file were retrieved, changed, and stored to a variable by the attacker. This was done multiple times. Submit the last full PowerShell line that performed only these actions. *$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}*
- 4. After storing the altered file contents into the variable, the attacker used the variable to run a separate command that wrote the modified data to a file. This was done multiple times. Submit the last full PowerShell line that performed only this action. *$foo | Add-Content -Path 'Recipe'*
- 5. The attacker ran the previous command against a file multiple times. What is the name of this file? *Recipe.txt*
- 6. Were any files deleted? (Yes/No) *yes*
- 7. Was the original file (from question 2) deleted? (Yes/No) *no*
- 8. What is the Event ID of the log that shows the actual command line used to delete the file? *4104*
- 9. Is the secret ingredient compromised (Yes/No)? *yes*
- 10. What is the secret ingredient? *honey*

#### Suricata Regatta



### Recover the Elfen Ring

#### Clone with a Difference

#### Prison Escape

#### Jolly CI/CD



### Recover the Web Ring

#### Naughty IP

#### Credential Mining

#### 404 FTW

#### IMDS, XXE, and Other Abbreviations

#### Open Boria Mine Door

#### Glamtariel's Fountain

### Recover the Cloud Ring

#### AWS CLI Intro

#### Find the Next Objective

#### Trufflehog Search

#### Exploitation via AWS CLI



### Recover the Burning Ring of Fire

#### Buy a Hat

#### Exploit a Smart Contract


