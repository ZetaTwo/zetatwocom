---
layout: post
title: Solving the GCHQ christmas challenge with Microsoft Z3
status: published
type: post
published: true
comments: true
categories: ctf
---

British intelligence agency GCHQ has released a christmas card.
It contains a sudoku like puzzle where you color squares in a grid according to a set of constraints.
The christmas card challenge along with a description can be found on [their website](http://www.gchq.gov.uk/press_and_media/news_and_features/Pages/Directors-Christmas-puzzle-2015.aspx).
It looked like it could be solved by hand without too much effort but I figured it would be more fun to write a program to solve it for me.
Recently I have been playing with Microsoft's constraint solver, [Z3](https://github.com/Z3Prover/z3). I thought this would be a perfect tool to solve the challenge with.
 
As stated previously, the challenge consists of a grid, specifically a 25x25 grid with series of numbers written next to each column and row and with some of the cells already filled in.
Below is an image of the grid. Apparently, this is famous type of puzzle called a [Nonogram](https://en.wikipedia.org/wiki/Nonogram). I didn't know this until after I wrote this and a friend pointed it out.
You know what they say, you learn something every day.

![The GCHQ christmas challenge grid](/assets/images/ctf/gchq_christmas_card.jpg)

The rules of the challenge are that each number in a series denotes the size of a block of sequentially filled (black) cell separated by at least one unfilled (white) cell.
Series next to a row governs the pattern for that row and the ones above a column governs that column respectively.

Z3 is a theorem prover by Microsoft research which solves a model consisting of a number of variables given a set of constraints.
The challenge is to formulate the problem as a set of constraints that Z3 can process and give us a solution for.

In the end, the solution consisted of the four steps as outlined below.

1. Define spacers and blocks
2. Constrain sum of spacers and blocks sizes for rows and columns separately
3. Relate block and spacer sizes to cell color
4. Solve for both columns and rows simultaneously

I'll go through how I arrived at the solution step by step. 

My first attempt was to look at a single row and see how we can express that in Z3.
We know the sizes of the sequentially filled cells, which I call blocks, but we don't know the sizes of the unfilled sequences, which I call spacers.
Therefore, we add the size of these spacers as variables in Z3. We know that the spacers must be of at least size 1 since otherwise it wouldn't be a space.
As I Wasn't completely clear on the wording the challenge, I also added spacers on the edges which I did allow to be of size 0.

{% highlight python %}
rule_spacer_vals=[]
...
spacers.append([])
...
for x in range(len(row)+1):
    # Spacer sizes
    spacers[-1].append(Int('space_%d_%d' % (y,x)))

    # Edges can be zero size
    if x > 0 and x < len(row):
            rule_spacer_vals.append(spacers[-1][-1] >= 1)
    else:
            rule_spacer_vals.append(spacers[-1][-1] >= 0)
...

{% endhighlight %}

Something else we do know is that the sum of the sizes of all the blocks and spacers in a row must add up to the length of the row.
I didn't know how to create a sum of a dynamic set of variables using the Z3 Python bindings so to get around this I used many variables representing the partial sum of the sizes, adding one element at a time.
Each such partial sum consists of the size of the current element, which is either an unknown if we are working with a spacer, or a constant if we are working with a block, plus the previous partial sum.
The partial sums are also always positive. At the end we add the constraint that the last partial, which is actually no longer a partial but the full sum, must be equal to the size of the row

{% highlight python %}
rule_partials_vals=[]
rule_spacer_vals=[]
rule_partials=[]
...
# Cumulative size
partials.append([Int('part_%d_x0' % (y))])
rule_partials_vals.append(partials[-1][-1] == 0)
...
for x in range(len(row)+1):
   ...
   # Partial size of last space
   partials[-1].append(Int('part_space_%d_%d' % (y,x)))
   rule_partials_vals.append(partials[-1][-1] >= 0)
   rule_partials.append(partials[-1][-2] + spacers[-1][-1] == partials[-1][-1])
   
   ...
   
   # Block sizes
   if x < len(row):
       # Partial size of last block
       partials[-1].append(Int('part_block_%d_%d' % (y,x)))
       rule_partials_vals.append(partials[-1][-1] >= 0)
       rule_partials.append(partials[-1][-2] + row[x] == partials[-1][-1])
   
   ...

# Add up to row width
rule_partials.append(partials[-1][-1] == size)

...

{% endhighlight %}

Adding this to the Z3 solver indeed gives us possible solutions for a row independent of the constraints for the columns.
This means that at this stage it was possible to solve for the row constraints and the column constraints individually.
However, to get the actual solution, we need to solve for all constraints together.
For this, a natural way to proceed was to in some way model the color of the cells as unknowns with either value 0, for white, or value 1, for black.
We also force the value of the cells that were pre-filled.

{% highlight python %}

rule_dot_vals=[]
...
# Create pixels
dots = []
for y in range(size):
    dots.append([])
    for x in range(size):
        dots[-1].append(Int('dot_%d_%d' % (y,x)))
        rule_dot_vals.append(Or(dots[-1][-1] == 0, dots[-1][-1] == 1))
 
# Force blacks
for y,x in black:
    rule_dot_vals.append(dots[y][x] == 1)
...
{% endhighlight %}

Now, the difficult part was to somehow relate the sizes of the blocks and the spacers to the color of the cells.
Here, the partial sums, which I originally had created because I didn't know how to sum my values, turned out to be the solution.
If we are currently looking at block of _known_ size X and we have a previous partial sum of value Y, the new partial sum X+Y can be called Z.
If a cell lies between Y and Z, i.e. between Y and Y+X, we know that this cell must be black.
In the same way, if we are processing a spacer of _unknown_ size X, we know that cells lying between Y and Y+X must be white.
Now, we can't really use the index of a cell as constraint but we can create if-clauses for all possible positions.

{% highlight python %}

for x in range(len(row)+1):
    ...

    # Add white constraint
    for x2 in range(size):
            rule_dots_cover.append(If(And(partials[-1][-2] <= x2, x2 < partials[-1][-1]), dots[y][x2]==0, dots[y][x2]>=0))
    ...
    # Block sizes
    if x < len(row):
        ...           

        # Add black constraint
        for x2 in range(size):
                rule_dots_cover.append(If(And(partials[-1][-2] <= x2, x2 < partials[-1][-1]), dots[y][x2]==1, dots[y][x2]>=0))

{% endhighlight %}

Now we have created constraints relating the sizes of the spacers to the value of the cells. 
Repeating this for the column constraints and inserting it all into the Z3 solver gives us a solution model.
To turn this model into a human readable solution for the challenge, we loop over all the coordinates and evaluate the value of that cell.
As bonus, I used Pillow to create an image of it and saving it.

{% highlight python %}

s = Solver()
s.add(rule_spacer_vals)
s.add(rule_partials_vals)
s.add(rule_dot_vals)
s.add(rule_partials)
s.add(rule_dots_cover)

if s.check() == sat:
    m = s.model()

    im = Image.new('L', (size+2,size+2), 255)
    for y in range(size):
        row=[]
        for x in range(size):
            pixel = m.evaluate(dots[y][x]).as_long()

            if pixel == 0:
                    im.putpixel((x+1,y+1), 255)
            else:
                    im.putpixel((x+1,y+1), 0)
            row.append(str(pixel))
        print(''.join(row))
    im=im.resize((16*(size+2),16*(size+2)))
    im.show()
    im.save('result.png')
else:
    print('Fail')

{% endhighlight %}

This gives us the following QR code as solution to the puzzle.

![QR code solution to the GCHQ christmas challenge](/assets/images/ctf/gchq_christmas_solution.png)

~~Strangely enough, this code was not readable by "zbarimg" but the QR scanner on my phone worked and online tools as well.~~
Update: I had accidentally transposed the image by calling _im.putpixel((y,x))_ instead of _im.putpixel((x,y))_. Thanks camitz for pointing this out. With that corrected, even "zbarimg" reads the QR code correctly.
The QR code leads to the next stage of the christmas challenge.
I'm just a beginner with Z3 and there are probably better ways to do this.
If you have any feedback or ideas, please post a comment below. For completeness, here is the [full solution script](/assets/other/gchq_christmas_code.py)
 
Merry christmas!
