#!/usr/bin/env python

# Author: Calle "Zeta Two" Svensson <calle.svensson@zeta-two.com>
# Solution to http://www.gchq.gov.uk/press_and_media/news_and_features/Pages/Directors-Christmas-puzzle-2015.aspx

from z3 import *
from PIL import Image

size=25
rules = [
[7,3,1,1,7],
[1,1,2,2,1,1],
[1,3,1,3,1,1,3,1],
[1,3,1,1,6,1,3,1],
[1,3,1,5,2,1,3,1],
[1,1,2,1,1],
[7,1,1,1,1,1,7],
[3,3],
[1,2,3,1,1,3,1,1,2],
[1,1,3,2,1,1],
[4,1,4,2,1,2],
[1,1,1,1,1,4,1,3],
[2,1,1,1,2,5],
[3,2,2,6,3,1],
[1,9,1,1,2,1],
[2,1,2,2,3,1],
[3,1,1,1,1,5,1],
[1,2,2,5],
[7,1,2,1,1,1,3],
[1,1,2,1,2,2,1],
[1,3,1,4,5,1],
[1,3,1,3,10,2],
[1,3,1,1,6,6],
[1,1,2,1,1,2],
[7,2,1,2,5]
]

rules2 = [
[7,2,1,1,7],
[1,1,2,2,1,1],
[1,3,1,3,1,3,1,3,1],
[1,3,1,1,5,1,3,1],
[1,3,1,1,4,1,3,1],
[1,1,1,2,1,1],
[7,1,1,1,1,1,7],
[1,1,3],
[2,1,2,1,8,2,1],
[2,2,1,2,1,1,1,2],
[1,7,3,2,1],
[1,2,3,1,1,1,1,1],
[4,1,1,2,6],
[3,3,1,1,1,3,1],
[1,2,5,2,2],
[2,2,1,1,1,1,1,2,1],
[1,3,3,2,1,8,1],
[6,2,1],
[7,1,4,1,1,3],
[1,1,1,1,4],
[1,3,1,3,7,1],
[1,3,1,1,1,2,1,1,4],
[1,3,1,4,3,3],
[1,1,2,2,2,6,1],
[7,1,3,2,1,1]
]

black = [
	(3,3),(3,4), (3,12),(3,13), (3,21),
	(8,6),(8,7), (8,10),  (8,14),(8,15),  (8,18),
	(16,6),(16,11),(16,16),(16,20),
	(21,3),(21,4),(21,9),(21,10),(21,15),(21,20),(21,21)
]

# Print solution
def solve(s, dots):
	if s.check() == sat:
		m = s.model()
		#print(m)

		im = Image.new('L', (size+2,size+2), 255)
		for y in range(size):
			row=[]
			for x in range(size):
				pixel = m.evaluate(dots[y][x]).as_long()

				if pixel == 0:
					im.putpixel((y+1,x+1), 255)
				else:
					im.putpixel((y+1,x+1), 0)
				row.append(str(pixel))
			print(''.join(row))
		im=im.resize((16*(size+2),16*(size+2)))
		im.show()
		im.save('result.png')
	else:
		print('Fail')

# Create rulesets
rule_dots_cover=[]
rule_partials=[]
rule_dot_vals=[]
rule_partials_vals=[]
rule_spacer_vals=[]

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

# Parse horizintal rules
spacers = []
partials = []
for y in range(len(rules)):
	row = rules[y]

	# Cumalative size
	partials.append([Int('part_%d_x0' % (y))])
	spacers.append([])

	rule_partials_vals.append(partials[-1][-1] == 0)

	for x in range(len(row)+1):
		# Spacer sizes
		spacers[-1].append(Int('space_%d_%d' % (y,x)))

		# Edges can be zero size
		if x > 0 and x < len(row):
			rule_spacer_vals.append(spacers[-1][-1] >= 1)
		else:
			rule_spacer_vals.append(spacers[-1][-1] >= 0)

		# Partial size of last space
		partials[-1].append(Int('part_space_%d_%d' % (y,x)))
		rule_partials_vals.append(partials[-1][-1] >= 0)
		rule_partials.append(partials[-1][-2] + spacers[-1][-1] == partials[-1][-1])

		# Add white constraint
		for x2 in range(size):
			rule_dots_cover.append(If(And(partials[-1][-2] <= x2, x2 < partials[-1][-1]), dots[y][x2]==0, dots[y][x2]>=0))

		# Block sizes
		if x < len(row):
			# Partial size of last block
			partials[-1].append(Int('part_block_%d_%d' % (y,x)))
			rule_partials_vals.append(partials[-1][-1] >= 0)
			rule_partials.append(partials[-1][-2] + row[x] == partials[-1][-1])		

			# Add black constraint
			for x2 in range(size):
				rule_dots_cover.append(If(And(partials[-1][-2] <= x2, x2 < partials[-1][-1]), dots[y][x2]==1, dots[y][x2]>=0))

	# Add up to row width
	rule_partials.append(partials[-1][-1] == size)

# Parse vertical rules
spacers2 = []
partials2 = []
for x in range(len(rules2)):
	col = rules2[x]

	# Cumalative size
	partials2.append([Int('part2_%d_y0' % (x))])
	spacers2.append([])
	rule_partials_vals.append(partials2[-1][-1] == 0)
	
	for y in range(len(col)+1):
		# Spacer sizes
		spacers2[-1].append(Int('space2_%d_%d' % (y,x)))

		# Edges can be xero size
		if y > 0 and y < len(col):
			rule_spacer_vals.append(spacers2[-1][-1] >= 1)
		else:
			rule_spacer_vals.append(spacers2[-1][-1] >= 0)

		# Partial size of last space
		partials2[-1].append(Int('part2_space_%d_%d' % (y,x)))
		rule_partials_vals.append(partials2[-1][-1] >= 0)
		rule_partials.append(partials2[-1][-2] + spacers2[-1][-1] == partials2[-1][-1])

		# Add white constraint
		for y2 in range(size):
			rule_dots_cover.append(If(And(partials2[-1][-2] <= y2, y2 < partials2[-1][-1]), dots[y2][x]==0, dots[y2][x]>=0))

		# Block sizes
		if y < len(col):
			# Partial size of last block
			partials2[-1].append(Int('part2_block_%d_%d' % (y,x)))
			rule_partials_vals.append(partials2[-1][-1] >= 0)
			rule_partials.append(partials2[-1][-2] + col[y] == partials2[-1][-1])

			# Add black constraint
			for y2 in range(size):
				rule_dots_cover.append(If(And(partials2[-1][-2] <= y2, y2 < partials2[-1][-1]), dots[y2][x]==1, dots[y2][x]>=0))

	# Add up to col height
	rule_partials.append(partials2[-1][-1] == size)

# Add rulesets to solver
s = Solver()
s.add(rule_spacer_vals)
s.add(rule_partials_vals)
s.add(rule_dot_vals)
s.add(rule_partials)
s.add(rule_dots_cover)

# Show solution
solve(s, dots)