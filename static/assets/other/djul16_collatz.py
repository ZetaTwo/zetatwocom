def get_count(n):
    i = 1
    while n != 1:
        (n, i) = (3*n+1 if n%2 else n/2, i + 1)
        yield (n, i)

for i in range(1,100):
	c = get_count(i)
	for x in c:
		if x[0] == 1456:
			print('START', i)
			break
		if x[0] == 1:
			break
