---
layout: page
title: Trainings
permalink: /services/trainings
---

## Basics of Binary Exploitation

This is the training I gave at [Security Fest](https://securityfest.com/speakers/2019/training-basics-of-binary-exploitation/) and [SEC-T](https://www.sec-t.org/archive/2019_events/trainings/basics-of-binary-exploitation-training/) during 2019.
It is a basic training that serves as an introduction to the area of binary exploitation.
The text below is a copy of the information available on the SEC-T registration page.
If you or your organisation is interested in buying a training on this topic, please contact me at calle.svensson@zeta-two.com

### Overview

Binary exploitation is the topic concerning the finding and exploitation of vulnerabilities in low-level code, particularly machine level code. It is usually considered one of the more complex areas of IT security and some of the exploits produced sometimes chain together dozens of moving parts in mind-boggling ways to cause programs to behave in a completely unintended manner. The field is the basis of high-severity exploits such as OS privilege escalation, jailbreaks and browser exploits.

### Learning goals and expected outcomes

This two-day training aims to give the participant a deeper understanding of how programs execute and interact with the rest of the system, an understanding of the basic building blocks, terminology and anatomy of binary exploitation as well as hands on experience and creating some basics exploits of their own. It will also cover various protection mechanisms, how they work and how to deal with them. Throughout the course, techniques for finding vulnerabilities, analyzing and turning them into exploits will be covered and practiced in the form of hands on exercises.

After completing the training the student will have a solid foundation from which they can continue exploring the field of binary exploitation and allowing them to start learning advanced topics such as kernel exploitation, different architectures and exploiting real-world software such as browsers and phones. The student will also have a basic understanding of some of the various techniques used for working with analysis and exploitation of programs.

### Course contents

The course will cover the following topics will be covered in the course. Topics marked with `*` will be covered as part of the introduction/background without accompanying exercises. Topics marked with `**` are advanced topics covered as part of an introduction into how to proceed after the training.

* Stack based attacks
   - Buffer overflow
   - ROP
   - Stack shifting
   - Format string attacks
* Heap based attacks
   - Buffer overflow
   - Use-after-free
   - Type confusion
* General concepts
   - Memory layout*
   - x86 basics*
   - Writing exploits
   - Function pointers (vtables)
* Program analysis
   - Fuzzing
   - Symbolic execution
   - Debugging
   - Tracing
* Exploit primitives
   - Arbitrary read (absolute, relative)
   - Arbitrary write (absolutely, relative)
* Protections
   - Stack canaries
   - NX/DEP
   - ASLR + PIE
   - CFG**
   - PAC**

### Outline

Below is a rough outline of the planned schedule for the training. This is preliminary and subject to change. A more definitive schedule will be posted prior to the training.

* Day 1
  - Intro
  - Stack exploit basics
  - Protection mechanisms
  - Format string vulnerabilities
  - Heap exploit basics
* Day 2
  - Fuzzing
  - Symbolic execution
  - Debugging
  - More exploit exercises

### Tools used

We will be using mostly free and open source tools throughout the training. Programs will be debugged with gdb with the pwndbg addon. The exercises can be solved with a programming language of your choice but examples will be presented in Python with the pwntools framework.

The only commercial tool we will use is Binary Ninja which is a reverse engineering platform. A personal non-commercial license for Binary Ninja is included in the price of the training which you get to keep and can, if desired be upgraded to a commercial license. All tools and exercises will be available as a pre-packaged VM/container. Instructions on how to obtain and get it set up on your computer will be provided to all participants ahead of the training.

### Prerequisites

The student is expected to have basic understanding of computers, programs and operating systems. Some basic programming skills are also required, particularly some basic Python knowledge is very helpful. Finally it is expected that the student can read simple C code and understand very basic concepts of assembler.

### The instructor

Carl Svensson is a security professional and hobbyist currently working as the head of security at Swedish healthcare startup, KRY. He is a frequent CTF player for the Swedish top team HackingForSoju and an active member of the Swedish and international security community with a great fondness for a broad range of topics, reverse engineering being one of his favorites. If you have questions about the contents of this training, feel free to get in touch at calle.svensson@zeta-two.com.
