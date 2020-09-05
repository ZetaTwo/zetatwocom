---
layout: post
title: Generating uniform random numbers
date: 2015-05-18 23:55
type: post
published: true
comments: true
categories: math
---

We have all probably at some point in our programming career been required to generate a uniformly distributed random number in an interval {% katex %}[A,B]{% endkatex %}.

# The mistake

For this you might have done something along the lines of:

{% highlight c %}
int x = A + (rand() % (B-A));
{% endhighlight %}

or maybe even:

{% highlight c %}
int x = A + (int)((float)rand())/RAND_MAX) * (B-A));
{% endhighlight %}

The idea behind the first being to wrap around within the desired range and the second to stretch or shrink the range of rand().
Now, depending on the application, both of these methods might work just fine, or they might be downright dangerous.
Regardless, who settles for just fine? That's right, not you. So what is the problem with these methods?

For the first method imagine for a moment that RAND_MAX is for example 255. In reality it is hopefully not, but the idea still holds.
Let's also say we are generating a number in {% katex %}[1,100]{% endkatex %}. Now we have a problem, the rand() function has 256 different outcomes which we want to assign to 100 different outcomes.
This is simply not possible. All numbers {% katex %}[1,100]{% endkatex %} will have at least two outcomes assigned to them, namely i and i+100.
However, the first 56 numbers will have another outcome assigned to them from the remaining 56 outcomes of rand().
This means that for example the number 5 will be 50% more likely to occur than 73.
This also means that the average of a series of outcomes of this method will be significantly less than 50 which is what you would expect.

The problem with the second method could be attributed to rounding. Some outcomes will have more number that are rounded to it.
I claim however that this is simply the same problem in disguise. We are trying to map 256 outcomes onto 100 outcomes. No mathematical trickery will help you accomplish this.

# The solution
How do you do this then? How do you use a function which gives you a uniformly distributed random value in one range to create a new function which gives you a uniformly distributed random number from another range?
The engineer answer to this is of course: you don't. You use a library that someone smarter than you have created. In C++ this can be done with the C++11 [\<random\>](http://en.cppreference.com/w/cpp/numeric/random) header.

# The explanation
But how does this work? It can be implemented in several ways but I will approach this with a concept of an entropy pool. Let's say we have a source range {% katex %}[A,B]{% endkatex %} and a target range {% katex %}[C,D]{% endkatex %}.
First of all, we don't care about the offset, generating a number in {% katex %}[0,4]{% endkatex %} is exactly the same as generating a number in {% katex %}[5,9]{% endkatex %}. You simply take a value from the first range and add 5 to get a number in the second range.
From now on {% katex %}X=B-A{% endkatex %} and {% katex %}Y=D-C{% endkatex %}. The problem is thus, to transform a number from {% katex %}[0,X]{% endkatex %} to {% katex %}[0,Y]{% endkatex %}.

The centerpiece of this play will be the entropy pool, which is just a fancy name for a list of uniformly distributed bits.
That is, they have exactly 50% probability of being either 0 or 1.
The process can thus be divided into getting these "good" bits into the list and using them to create a random number.
Creating a number is easy, let's say that {% katex %} m = \lceil log_2(Y) \rceil {% endkatex %}, that is we need m bits to represent Y. Then we simply take m bits from the list and create a number from them.
We then check that the number is at most Y, if so, we output it, otherwise, we try again.
In the worst case, when Y is chosen to be {% katex %} 2^i {% endkatex %} for some i we will have to throw away roughly half of the numbers generated but that's not too bad.
To get numbers into the pool we generate a number from the input range. If {% katex %}n = \lfloor log_2(X) \rfloor{% endkatex %}, we check that the generated number is within {% katex %} [0,2^n) {% endkatex %}.
If it is then we know that all the bits of the generated numbers have exactly 50% probability of being 1 or 0, assuming the input function is uniformly distributed of course.
In this case we take all the bits of the number and put them in the list. Otherwise, we throw away the number and try again. Similarly to the output part this may have to be done about half the time in the worst case.
In total we throw away half the numbers on the way in and half the numbers on the way out but we end up with perfectly uniformly distributed numbers.

# Improvements
Can we do better? Of course we can and there have been some interesting research on this but there are already quite obvious improvements.
For instance, instead of completely throwing away bad input numbers it is possible to treat the number as coming from a smaller range and use some of the bits from it.
Likewise, instead of rejecting bad output numbers, it is possible to use bits from it and complement it with a few more bits to get a good output.
Of course both of these improvements makes the implementation more complicated.
