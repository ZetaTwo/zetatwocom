---
layout: post
title: "PoliCTF 2015: Writeups"
date: 2015-07-14 13:49
type: post
published: true
comments: true
categories: math
---

This weekend we participacted in [PoliCTF](http://polictf.it), a CTF arranged by Italian team [Tower of Hanoi](towerofhanoi.github.io).
It was a very well arranged 48 hours CTF with good variety and minimal amount of guesswork.
We had five players working throughout the weekend: mxn, capsl, ZetaTwo, avlidienbrunn and hspe.
We performed very well and ended up on [second place](http://polictf.it/scoreboard/ranking).
This brought us up to 12th place on the [season scoreboard](https://ctftime.org/stats).
In this post I will explain the challenges I solved:

* [Crypto 50: Exorcise](#crypto50-exorcise)
* [Pwnable 100: John Pastry Shop](#pwnable100-john-pastry-shop)
* [Grab Bag 100: John the Dropper](#grabbag100-john-the-dropper)
* [Web 100: John the Traveller](#web100-john-the-traveller)
* [Web 350: Magic chall](#web350-magic)
* [Forensics 100: It's Hungry](#forensics100-hungry)

Total contribution: 800

If you want to read more writeups from this CTF, there is [a great GitHub repo with them](https://github.com/ctfs/write-ups-2015/tree/master/polictf-2015)

## <a name="crypto50-exorcise"></a>Crypto 50: Exorcise

Thanks to a mistake I actually solved this one in an unnecessarily complicated way.
The challenge provided a service which you could send text to and get it and some other text back encrypted.
The encryption was a simple repeated XOR with the flag as a key.

A message {% latex %}m{% endlatex %} is sent which get concatenated with some dummy text {% latex %}m'=a|m|b{% endlatex %}.
Then, each characted (byte) is XOR:ed with the current byte of the key {% latex %}c_i = m'_i \oplus k_i{% endlatex %}.
However, if we know two of three operands of the XOR operation we can recover the third by XOR:ing the other two. 

{% latex %}c_i \oplus m'_i = k_i \oplus m'_i \oplus m'_i = k_i{% endlatex %}

The easy way to solve this would have been to just send a long string of for example A's and then XOR the cipher you get back with the same message you sent.
Unfortunately, I made a mistake and thought that the encryption was more complicated than it was and turned this into an oracle attack.
By sending short messages of a single byte repeated, I figured out that the length of  {% latex %}a{% endlatex %} was 3.
Then I tried one value for first byte of {% latex %}m{% endlatex %} and with the help of the response, I calculated which byte was in the key.
I then repeated this for each byte in the message until I had the full key.

Flag: flag{_this_1s_s0_simple_you_should_have_solved__it_1n_5_sec}


## <a name="pwnable100-john-pastry-shop"></a>Pwnable 100: John Pastry Shop

This challenge was quite interesting. It provided a service to which you could send a specially encoded JAR-file.
If this JAR file was properly encoded, signed and contained a certain class, that class would be used in a program.
The program would instantiate the class, run addIngredientsToCake() on it and then print out a list of ingredients in the cake.

The first step was to write a decoder and encoder to be able to transform the _ShamanoCakeContainerEncoded.jar_ back and forth to a regular JAR.
A file _Decode.java_ was given in which the encoding scheme was described.
It was simply wrapping the JAR contents in a start-byte, 0x17, and a stop byte, 0x19, while escaping regular bytes with that value with 0x18.

The contents of the JAR were signed with an RSA key we didn't have.
Any modification to the signature or trying to remove it caused the service not to accept the JAR. 
However, I tried signing it again with another key I had created and self-signed.
This modification to the JAR didn't give any error. I then created another self-signed certificate with the exact same fields of the original certificate.
This worked and the JAR was accepted. It took a few moments more to get the flag however.
After fiddling around with some shell commands and trying to find a flag file I found this peculiar code in the provided _Cake.java_

{% highlight java %}
public abstract class Cake {

    protected boolean shouldBeAddedTheSpecialIngredient;
    protected List<String> ingredientsList;

    // Zero constructor
    protected Cake() {
        shouldBeAddedTheSpecialIngredient = false;
        ingredientsList = new LinkedList<>();
    }
    
    ...
}
{% endhighlight %}

I really felt that I wanted that special ingredient in my cake and submitted the following class in the JAR:

{% highlight java %}

public class NewYorkCheeseCake extends Cake
{
  public void addIngredientsToCake()
  {
  	this.shouldBeAddedTheSpecialIngredient = true;
  }
}

{% endhighlight %}

This printed out the flag in the ingredient list.

Flag: flag{PinzimonioIsTheSecretIngredientAndANiceFlag}


## <a name="grabbag100-john-the-dropper"></a>Grab Bag 100: John the Dropper

In this challenge, we were given the address to a server _dropper.polictf.it_. However, the server didn't seem to do anything useful.
It had no ports open at all except the admin SSH interface, but it was alive and responded to pings.

However, there was a strange behaviour. If you pinged it continuously, you noticed that it dropped some pings and responded so some.
 
{% highlight bash %}

64 bytes from ec2-52-18-119-20.eu-west-1.compute.amazonaws.com (52.18.119.20): icmp_seq=1 ttl=49 time=54.6 ms
64 bytes from ec2-52-18-119-20.eu-west-1.compute.amazonaws.com (52.18.119.20): icmp_seq=3 ttl=49 time=55.3 ms
64 bytes from ec2-52-18-119-20.eu-west-1.compute.amazonaws.com (52.18.119.20): icmp_seq=5 ttl=49 time=55.1 ms
64 bytes from ec2-52-18-119-20.eu-west-1.compute.amazonaws.com (52.18.119.20): icmp_seq=7 ttl=49 time=56.3 ms
...

 {% endhighlight %}
 
Treating a drop as a 1 and a response as a 0, you got the following sequence.

> 010101001110111011100101010000011110101010100101001010100000101001
> 010100000111001010101001000001010111010010111010100101110011101110
> 100101110111010111001010011100111010101010111001010010101001110101
> 010101110011101001001010101110010010111010011101010101011100111001
> 110111011100111011101110011101010101011100101110101001011100111001
> 001110101010101110010101110100111011101110010111010011101010101011
> 100101110011101010101011100111010100101110100111011101110010111011
> 10100101110111010111011101

There is definitely some structure to this but at first it wasn't obvious at all. Trying to interpret it as ASCII gives nothing.
I also tried looking at it as bytes to see if it was some kind of file or other known format.
Finally, I realized that the ones almost always occurred alone or in groups of three.
I tried decoding it as morse code and got: sos6isistheflag?it-is-never-too-late-for-a-drop?
Obviously there was a mistake somewhere on the way but it's good enough to get the flag.

Flag: flag{it-is-never-too-late-for-a-drop}

## <a name="web100-john-the-traveller"></a>Web 100: John the Traveller

This challenge led us to a web site with a flight booking site.
It had a single search field in which you could search for a European capital.

![Search results for Helsinki](/assets/images/ctf/poli_traveller1.jpg)

The results for all cities seemed random and changed whenever you reloaded the page.
However, the hint text ended with "There he goes! Flight is booked so... hauskaa lomaa!".
Using Google, this led us to believe that Helsinki was of special interest.
Indeed, searching for Helsinki, we notice that the prices suddenly are in "px" instead of "EUR" and in a much narrower range.
Furthermore, we always get exactly six results. Looking at the HTML source we also found some new CSS classes.
Looking in the _bootstrap.min.css_ file these CSS classes are found in a media query block for devices which have a screen width between 620 and 640 pixels.
Using Chrome's developer tools, we went into mobile mode and set the viewport to 640px wide and suddenly the page turned into this:

![Search results on a narrow screen](/assets/images/ctf/poli_traveller2.jpg)

Decoding the QR code gives us the flag.

Flag: flag{run_to_the_hills_run_for_your_life}


## <a name="web350-magic"></a>Web 350: Magic chall

I felt like this challenge was almost made for me. A few weeks ago, I was at [Confidence](http://confidence.org.pl) to compete.
As a part of that, I gave a talk about PHP's file stream features and what problems that can lead to.
This was exactly what was used here to get source disclosure.

The website had a simple login page and a registration where you could enter name, last name, username and password.
When logging in you got to a page with a random video. The interesting part was in the URL.
Pages were accessed by going to /index.php?page=X where X was for example "login".
If we instead changed this to: 

> http://magic.polictf.it/index.php?page=php://filter/convert.base64-encode/resource=index

We got the contents of index.php outputted as base64 encoded text. This was then decoded to reveal the code.
The index page included several classes and using the same technique, we could get the source of them all.
Two parts of the code were particularly interesting. First, in the Logger class I found:

{% highlight PHP %}

<?php

class Logger{
private $host, $filename, $user;

	public function __construct($host, $user){
		...
		$this -> filename = $_SERVER["DOCUMENT_ROOT"]."log/" . $host . "_" . $user->getSurname();
		...
	}

	public function log_access(){
		...
		$write = fwrite($fo, date('l jS \of F Y h:i:s A') . " - " . $this -> user -> getUsername() .": log in success\n");
		...
	}
	
	public function initLogFile(){
		...
		$write = fwrite($fo, "name|".$this -> user -> getName().";surname|".$this->user->getSurname().";date_creation|UTC:".date('l jS \of F Y h:i:s A')."\n");//write header in logfile.
		...
	}
}

{% endhighlight %}

So by creating a user with PHP code as its name, anything as its last name, we can include the log file from the index page by accessing:

> http://magic.polictf.it/index.php?page=log/X_Y

where X is your hostname and Y is the lastname of the user minus ".php"

In the Magic class, I found:

{% highlight PHP %}

<?php

class Magic{

	public function __construct() {
	}

	...

	public function __call($iveNeverSeenAnythingSoMagical, $magicArguments) {
		...
		echo "I THINK THIS IS THE VERY MAGIC THING: " . $magic_word;
	}
}

{% endhighlight %}

Which indicated that we want to create a Magic object and call any function on it.
I registered a user with name "<?php $a = new Magic(); $a->x(); ?>" and lastname "x.php".
After logging in with the user once, I used the indedx page to include the log file and get the flag.
Of course, it would have also been possible to directly access the log file, but that is something you easily don't think about at 3am.

Flag: flag{session_regenerate_id()_is_a_very_cool_function_use_it_whenever_you_happen_to_use_session_start()}

## <a name="forensics100-hungry"></a>Forensics 100: It's Hungry

This challenge consisted of a song _oldmcdonald.flac_ and a text:

> 100 Points  Old McDonald had a farm. Old McDonald liked chiptune.
> He also needed to remind its daughter to take care about a zombie animal.
> But he wanted to do it discreetly, so he wrote this song. 
> Can you find the message? (all lowercase, no spaces) N.B. flag is not in format flag{.+}

First, I tried looking at metadata, there I found a red herring flag.
Then I tried looking at the song in a spectrogram and found a red herring like this:

![Mcdonald.flac in a spectrogram](/assets/images/ctf/poli_hungry.jpg)

Later in the spectrogram there was also a morse coded message with a red herring and a trollface.
Then I sent the file to my musical genius friend and asked him if he could write down the notes or find anything else of interest.
He sent back [the melody}(/assets/other/oldmcdonald_score.pdf) which clearly spells out the flag and fits with the hint.

Flag: feeddadeadbeef