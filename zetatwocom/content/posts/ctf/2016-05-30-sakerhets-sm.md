---
layout: post
title: "Säkerhets-SM 2016: Lösningar"
date: 2016-05-30 XX:XX
type: post
published: false
comments: false
categories: ctf
---

Säkerhets-SM 2016. Första gången. Tävling för högstadiet och gymnasiet. Länk till hemsida.
Kommer förklara alla problem. Grundläggande nivå. Kommentera gärna om frågor. Se fram emot nästa år.

* [Binär 30: Such binary](#binär-30-such-binary)
* [Binär 100: Much binary](#binär-100-much-binary)
* [Kryptografi 10: Macrohard](#kryptografi-10-macrohard)
* [Kryptografi 25: Lärarhack](#kryptografi-25-lärarhack)
* [Kryptografi 30: Caesar hälsar!](#kryptografi-30-caesar-hälsar)
* [Kryptografi 30: Ettor och nollor](#kryptografi-30-ettor-och-nollor)
* [Kryptografi 45: En exklusiv bokstav](#kryptografi-45-en-exklusiv-bokstav)
* [Kryptografi 50: Rock till Roll](#kryptografi-50-rock-till-roll)
* [Kryptografi 80: RSA](#kryptografi-80-rsa)
* [Forensik 15: En svart bild](#forensik-15-en-svart-bild)
* [Forensik 30: Mitt WiFi!](#forensik-30-mitt-wifi)
* [Forensik 30: Myrornas krig](#forensik-30-myrornas-krig)
* [Forensik 35: Castaway](#forensik-35-castaway)
* [Forensik 60: Huvud, axlar, knä & tå](#forensik-60-huvud,-axlar,-knä-&-tå)
* [Forensik 60: En svart bild 2](#forensik-60-en-svart-bild2)
* [Forensik 75: Resan till förståelse](#forensik-75-resan-till-förståelse)
* [Programmering 40: Teckenfrekvens](#programmering-40-teckenfrekvens)
* [Programmering 70: Regex](#programmering-70-regex)
* [Rekognisering 60: Författarna 1](#rekognisering-60-författarna-1)
* [Rekognisering 40: Författarna 2](#rekognisering-40-författarna-2)
* [Rekognisering 100: Författarna 3](#rekognisering-100-författarna-3)
* [Unix 15: SSH for dummies](#unix-15-ssh-for-dummies)
* [Unix 20: Unix för dummies](#unix-20-unix-för-dummies)
* [Web 20: What is the flag?](#web-20-what-is-the-flag)
* [Web 25: Alla möjligheter](#web-25-alla-möjligheter)
* [Web 35: Le Bank](#web-35-le-bank)
* [Web 60: Mupparna](#web-60-mupparna)
* [Web 70: Superhemliga klubben](#web-70-superhemliga-klubben)
* [Övrigt 25: Ekrpat](#ovrigt-25-ekrpat)


## <a name="binär-30-such-binary"></a>Binär 30: Such binary

### Förklaring


## <a name="binär-100-such-binary"></a>Binär 100: Much binary

### Förklaring

## <a name="kryptografi-10-macrohard"></a>Kryptografi 10: Macrohard

### Förklaring
* följ mönstret


## <a name="kryptografi-25-lärarhack"></a>Kryptografi 25: Lärarhack


### Förklaring
* https://crackstation.net/
* Sök


## <a name="kryptografi-30-caesar-hälsar"></a>Kryptografi 30: Caesar hälsar!

Meddelandet är krypterat med ett enkelt Caesar-chiffer. Förskjut varje bokstav med X för att ta fram det ursprungliga meddelandet.

### Förklaring
Ett Caesar-chiffer fungerar så att ett tal, som är mindre än antalet bokstäver i alfabetet, väljs.
Sedan byts varje bokstav i meddelandet som ska krypteras ut mot den bokstav som kommer så många steg efter i alfabetet.
Om vi exempelvis väljer nyckeln 4 så krypteras "AGENT X" till "EKIRX B". Notera att om slutet av alfabetet nås, så börjar det om från början, dvs. "X" blir "B".

För att dekryptera så är det bara att göra motsatsen, dvs. förskjuta bakåt lika många steg.
Vi vet inte vad nyckeln är men eftersom det bara finns ungefär 25 olika nycklar (beroende på vilket alfabet som används) så är det bara att testa allihopa och se vilket som ger läsbar text.
Genom att göra detta finner vi att nyckeln X meddelandet "ABC"

## <a name="kryptografi-30-ettor-och-nollor"></a>Kryptografi 30: Ettor och nollor

### Förklaring
* http://www.rapidtables.com/convert/number/binary-to-ascii.htm



## <a name="kryptografi-45-en-exklusiv-bokstav"></a>Kryptografi 45: En exklusiv bokstav

### Förklaring
* XOR
* Brute force


## <a name="kryptografi-50-rock-till-roll"></a>Kryptografi 50: Rock till Roll

Meddelandet är krypterat med ett enkelt substitutionschiffer. Genom att göra en frekvensanalys av bokstäverna kan man hitta en god ansats till lösningen.
Lite manuell korrigering ger sedan det ursprungliga meddelandet.

### Förklaring

Ett enkelt subtitutionschiffer fungerar så att varje bokstav ersätts med en annan bokstav.
Det betyder att, om vi använder 27 bokstäver så finns det 27! (~10^X, jättestort tal) olika tänkbara nycklar.
Vi kan inte testa alla dessa. Vi kan däremot göra en frekvensanalys av texten.

I alla språk är vissa bokstäver vanligare än andra. I engelska är t.ex. "e" den vanligaste bokstaven.
Det innebär att om meddelandet är på engelska från början så kommer den bokstav som förekommer flest gånger i den krypterade texten antagligen motsvara "e".

Eftersom detta är en svensk tävling gissar vi på att texten är på svenska.
Lite googlande ger oss teckenfrekvensen för svenska som vi då kan ställa upp bredvid teckenfrekvensen i det krypterade meddelandet:

X A
Y B
Z C

Genom att ersätta de bokstäver som är vanligast i texten med motsvarande rad i kolumnen bredvid får vi något som liknar en lösning.
Därifrån behövs lite manuellt rättande då fördelningen inte alltid stämmer helt. Tillslut får vi tillbaka meddelandet, en väldigt bra låt och flaggan.


## <a name="kryptografi-80-rsa"></a>Kryptografi 80: RSA

Den publika RSA-nyckeln består av två tal (e,n).
n är modulen och består av två primtal p och q som har multiplicerats ihop för att ge n.
Eftersom nyckeln är dåligt genererad går det att faktorisera n och få tillbaka p och q.
Dessa kan sedan användas för att räkna ut den privata nyckeln (d,n) och sedan dekryptera meddelandet.

### Förklaring
* openssl rsa -text -noout -pubin
* 304 bit, exponent 3
* försök faktorisera n
* dekryptera

`
sage: n = "00:a6:53:b2:8f:56:fd:c3:42:9d:13:dc:17:11:87:08:c4:e4:1f:e0:25:42:4e:41:f0:96:e5:c1:42:c8:c5:88:5b:dc:79:45:11:de:03".replace(':','')
sage: n = int(n,16)
sage: factor(n)
17 * 1245639586229205028632457445812614864825644528871873132924187723077786348488042903069053139
sage: p=17
sage: q=1245639586229205028632457445812614864825644528871873132924187723077786348488042903069053139
sage: phi=(p-1)*(q-1)
sage: d=inverse_mod(3,phi)
`

`
echo "jMN3Npf6cEvm5ut94ETYvJ4tKARS1WT0CX5yrYI76ALUrulAKwo=" | base64 -d | openssl rsautl -decrypt -inkey rsa.key
flaggan är en banderoll
`




## <a name="forensik-15-en-svart-bild"></a>Forensik 15: En svart bild

Genom att öppna bilden i ett bildbehandlingsprogram och höja kontrasten så ser man flaggan.

### Förklaring

Bilden är inte helt svart. Flaggan är helt enkelt skriven med väldigt mörk grå på svart bakgrund.
Skillnaden är dock så liten att det kan vara svårt att se texten. Genom att öka kontrasten på bilden så ökar skillnaden mellan färgerna och texten syns.


## <a name="forensik-30-mitt-wifi"></a>Forensik 30: Mitt WiFi!
### Förklaring
* Vanliga lösenord


## <a name="forensik-30-myrornas-krig"></a>Forensik 30: Myrornas krig



### Förklaring
* Överlappa

## <a name="forensik-35-castaway"></a>Forensik 35: Castaway

Genom att ta mellanslagen på varje rad och tolka det som morse-kod får man ordet "karmosin".

### Förklaring

Morsekod är ett äldre kommunikationssätt som har använts mycket i tidig trådlås kommunikation.
Genom att skicka korta och långa pulser kan man signalera bokstäver.
Om man tittar på dikten så har vissa ord flera mellanslag mellan sig medan vissa bara har ett.
Om man tolkar flera mellanslag som en lång puls och ett ensamt mellanslag som en kort puls så får man följande morse-kod:

`
----------
`

Genom att titta i en tabell eller använda en konverterare så får vi fram att detta blir "karmosin"

## <a name="forensik-60-huvud,-axlar,-knä-&-tå"></a>Forensik 60: Huvud, axlar, knä & tå
Om du öppnar bilden i ett ZIP-program så ser du att den innehåller en textfil som heter "flag.txt". Denna fil innehåller flaggan.

### Förklaring
En fil består av en sekvens av bytes. Filer är ordnade i olika filformat som 
beskriver i vilken ordning datan är sparad och hur de olika byte ska tolkas.
Två väldigt vanliga filformat är [PNG](WIKI) och [ZIP](WIKI).

PNG är ett bildformat som ofta används för t.ex. grafik så som loggor och banderoller.
ZIP är ett arkivformat som används för att lägga ihop och komprimera filer.
En PNG-fil börjar alltid med 8 st specifka byte som markerar att det är en PNG-fil.
Sist har PNG-formatet 4 byte som säger att här tar bilden slut. Det betyder att 
om det finns mer data efter dessa 4 byte så gör det ingenting eftersom det program som 
läser filen, t.ex. en bildvisare struntar i den datan.

ZIP-formatet är strukturerat så att först så ligger alltid 2 st specifika byte som markerar att det är en ZIP-fil.
Strax därefter kommer varje fil omgiven av vissa markörer och sist så kommer en innehållsförteckning.
Att innehållsförteckningen ligger sist och inte först har historiska skäl.
Det innebär också att ZIP-filer läses "bakifrån". En ZIP-läsare öppnar en ZIP-fil och
tittar längst bak i filen efter innehållsförteckningen.
Därifrån kan den sen leta upp var de olika filerna ligger.
Det innebär alltså att om det ligger extra data innan början av en ZIP-fil så gör det 
ingenting eftersom det går att läsa filen ändå.

Dessa två fakta tillsammans innebär att det går att ta en PNG-bild och 
ett ZIP-arkiv och lägga dem efter varandra i samma fil. 
Det går då att tolka filen både som en PNG-bild med extra skräpdata efter slutet, 
eller som ett ZIP-arkiv med extra skräpdata innan början.
Det kommer alltså att öppna filen både i en bildvisare och i ett ZIP-program.
Om man öppnar den i ett ZIP-program så ser man att den innehåller en ihoppackad fil som heter "flag.txt".
Denna fil innehåller flaggan.

## <a name="forensik-60-en-svart-bild2"></a>Forensik 60: En svart bild 2

### Förklaring
* Alpha

## <a name="forensik-75-resan-till-förståelse"></a>Forensik 75: Resan till förståelse
## <a name="programmering-40-teckenfrekvens"></a>Programmering 40: Teckenfrekvens

## <a name="programmering-70-teckenfrekvens"></a>Programmering 70: Regex
Genom att läsa det reguljära uttrycket så ser man att det finns 22 896 giltiga URL:er som matchar.
Ett program kan testa alla dessa på ett par minuter och hitta den enda av dem som är giltig.
Den giltiga URL:en innehåller flaggan.


### Förklaring
Reguljära uttryck, eller kort regexp, är sätt att beskriva mönster som man vill leta efter i text.
Exempelvis så matchar uttrycket "[a-c]{2,4}[x-z]?" både orden "aacz" och "abcax".
Uttrycket "(?:m|p)a\1\1a" matchar både ordet "mamma" och ordet "pappa".

Med regexp går det göra väldigt avancerade sökningar i data, antingen för att hitta eller ersätta den.
I detta fall är det angivet att URL:en där flaggan ligger gömd matchar det angivna mönstret.

Mönstret betyder att vi först vill undvika att matcha alla strängar som är minst 11 tecken långa.
Det betyder att det vi söker är upp till 10 tecken långt.
Nästa del innebär att vi matchar någon av siffrorna 0-3 två gånger. Det betyder att vi matchar "03" och "12" men inte "42" eller "24".
Efter detta kommer en del som matchar antingen bokstaven "a" eller "b" upprepad två gånger. Detta mönster kan sedan upprepas hur många gånger som helst.
Detta innebär alltså att vi kan matcha t.ex. "aabbaa" men inte "abab".

Efter detta krävs det att tecknet "_" kommer. Slutligen matchar vi någon av tecknena a-z, A-Z och "^".
Denna sista del är skriven medvetet knepigt. "\w" betyder alla bokstäver. "^" betyder just det tecknet i detta sammanhang.
Sedan är a-y listat igen vilket är överflödigt och bara till för att förvirra.

Om man räknar på det kan man komma fram till att det finns 4*4*3*3*3*53 = 22896 strängar som uppfyller dessa krav.
Detta är givetvis alldeles för mycket för att testa för hand. Däremot kan man skriva ett program som testar dessa åt en.

Hemsidor och kommunikationen som rör dem överförs genom ett protokoll som heter HTTP.
HTTP-protokollet specificerar ett antal status-koder som används för att indikera i vilken utsträckning servern kunde hantera din förfrågan.
Om allt har gått som det ska så kommer koden "200" att skickas, tillsammans med själva innehållet.
Om webservern inte kunde hitta något innehåll på den adress du bad om så kommer den att svara med kod "404".

Vi kan därför skriva ett program som testar samtliga 22896 kombinationer och slutar så fort den får tillbaka kod "200" från servern.
Jag skrev mitt program i Python och det ser ut såhär:

`
KOD
`

## <a name="rekognisering-60-författarna-1"></a>Rekognisering 60: Författarna 1


## <a name="rekognisering-40-författarna-2"></a>Rekognisering 40: Författarna 2

## <a name="rekognisering-100-författarna-3"></a>Rekognisering 100: Författarna 3
Titta i källkoden på https://zeta-two.com/about/ eller på GitHub i koden på https://github.com/ZetaTwo/zetatwocom/commit/b875aa252422803bf3ddde8c042dc8589a836a95 så hittar du flaggan.

### Förklaring
* arrangör
* djulkalender
* zetatwo
* hemsida/github

## <a name="unix-15-ssh-for-dummies"></a>Unix 15: SSH for dummies
Logga in med SSH på servern och läs filen flag.txt så hittar du flaggan.

### Förklaring
Secure Shell
* SSH
* klienter
* kommandon
* cat

## <a name="unix-20-unix-för-dummies"></a>Unix 20: Unix för dummies
Logga in på SSH-serven och sök i filen passwords.txt efter en rad som innehåller "carlsven" så hittar du flaggan.

### Förklaring
* grep

## <a name="web-20-what-is-the-flag"></a>Web 20: What is the flag?
## <a name="web-25-alla-möjligheter"></a>Web 25: Alla möjligheter
## <a name="web-35-le-bank"></a>Web 35: Le Bank
## <a name="web-60-mupparna"></a>Web 60: Mupparna
## <a name="web-70-superhemliga-klubben"></a>Web 70: Superhemliga klubben

## <a name="ovrigt-25-ekrpat"></a>Övrigt 25: Ekrpat

### Förklaring
* Dvorak
