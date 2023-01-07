

Alla injektionssårbarheter (SQLi, XSS, Response splitting, CMDi, etc) bygger på grundprincipen att man bryter sig ut ur ett visst parser-kontext. Data och kod blandas ihop. Detta händer oftast när data kombineras med kod utan hänsyn till kontexten. Det klassiska exemplet är att kombinera en SQL-förfrågan med en sträng från en extern källa. Den delen av koden där datan infogas är ursprungligen ett sträng-kontext som avslutas med ett citattecken. Här måste vi alltså hantera citattecken på ett speciellt sett om vi vill uttrycka det inom samma kontext. I detta fall lägga till ett backslash framför för att indikera att vi faktiskt vill ha ett citattecken och inte avsluta sträng-kontexten. Det viktiga här är att förstå att alla dessa olika attacker är olika manifestationer av samma grundprincip.
Det föråldrade sättet att se på detta är att prata om in- och utdata och att indatan ska "valideras" för att förhindra detta. Problemet är att du då implicit skapar en stark koppling mellan tillfället då indatan kommer in och alla ställen den kan komma att användas. Detta är extremt skört i längden.
Ta följande exempel. Du tar in en söksträng från en användare och som en del av resultatsidan matar du ut "...<h1>Sökresultat för X</h1>..." där X ersätts med vad de nu sökte på. Vi är nu i ett HTML-text-kontext och vet därför att det är farligt med "<" eftersom det öppnar ett annat kontext. Vi filtrerar därför det tecknet och är nöjda. Nu är datan "ren". Senare kommer man på att man vill ha lite schysst javascript på sidan och matar även ut "<script>var query = 'X';...</script>" och stoppar in samma data. Om en angripare nu har ett enkelcitattecken i datan så har de nu en XSS.
Det korrekta sättet att resonera kring detta är att inte tänka på in- och utdata utan istället alltid hantera datan i sin ursprungliga form precis fram tills dess att den ska användas. 
Om vi återgår till exemplet ovan så är det helt ok att användaren matar in "<script>alert(1);</script>';alert(1);/*". Vi tar den som den är. När den strängen matas ut i det första kontextet så kommer "<" att escape:as och ingen XSS sker. Samtidigt så kommer den escape:as på ett annat sätt i det andra kontextet så att ' ersätts med \' och ingen XSS sker där heller.
Koden blir robustare och varje del kan oberoende hantera datan för det kontextet som är aktuellt.
I ditt specifika fall när du använder en ORM så hanterar den denna escape:ing åt dig och du behöver inte ens tänka på detta alls.
Så, när kan man prata om indatavalidering? När du vet på förhand att indatan ska följa ett exakt mönster så kan du såklart validera den direkt vid inmatning. T.ex. om du förväntar dig ett personnummer så vet du vad som är giltigt och inte. Om du förväntar dig ett datum så kan du direkt säga att 2019-66-66 inte är giltigt, etc.
Kortfattat, indatavalidering är användbart för vissa saker men det har _absolut ingenting_ med injektionsattacker att göra. Det är ett föråldrat synsätt.