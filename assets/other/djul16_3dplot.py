import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')

px=[]
py=[]
pz=[]
with open('coords.txt', 'r') as f:
	for line in f:
		x,y,z = map(int, line.strip().split(','))
		ax.scatter(x,y,z)
plt.show()
#Flag: fiol