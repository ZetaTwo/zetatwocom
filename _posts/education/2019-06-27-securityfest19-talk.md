---
layout: post
title: "SecurityFest 2019 - Software Obfuscation with LLVM"
date: 2019-06-27 21:30
type: post
published: true
comments: true
categories: education
---

At the end of May, I gave a presentation at [SecurityFest 2019](https://securityfest.com/).
I talked about the code obfuscation and how to use the LLVM compiler framework to obfuscate code.
The [recorded talk is available at the SecurityFest YouTube channel](https://www.youtube.com/watch?v=bQpPdT7RDqQ) and you can [download the slides here](/assets/other/securityfest19-obfuscation-slides-errata.pdf).

## Errata

Unfortunately, I made some incorrect statements in the talk by mixing up some tools.
It doesn't really affect the main point of the talk but for completeness I thought I would write this errata to explain what was wrong and what it should have been.

Basically, I mixed up two different amazing tools by [Trail of Bits](https://www.trailofbits.com/): [McSema](https://github.com/trailofbits/mcsema) and [Manticore](https://github.com/trailofbits/manticore/).
In the talk, I say that Manticore is a tool in the LLVM ecosystem. This is incorrect. Manticore doesn't have anything with LLVM to do.
McSema on the other hand is a "framework for lifting x86, amd64, and aarch64 program binaries to LLVM bitcode".
In particular, on the sixth slide (at around minute 13 in the recording) I have listed Manticore as an example of an LLVM tool but it should say McSema.
Then towards the end of the presentation (at around minute 33 in the recording) there is a question about the difference 
between Manticore and angr I again say that Manticore is uses LLVM which is incorrect. Both of them use their own intermediate representation.
The rest of the answer discussing the difference between Ghidra and IDA is still valid though.

In short, disregard anything I said about Manticore in the presentation, it's mostly wrong.
Everything else in the presentation should be mostly correct.

## Pictures

Jesper (organizer) and I on the stage before my talk:
![Jesper (organizer) and I on the stage before my talk](/assets/images/education/secfest-calle-small.jpg)

Me, on stage talking about LLVM:
![Me, on stage talking about LLVM](/assets/images/education/secfest-calle-small.jpg)
