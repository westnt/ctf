"""
pwnable.kr-asm solution
author: Weston Silbaugh
"""

from pwn import *
import time
import sys

#concatinated with script output to
#differentiate script and service output
idd = "[run.py] "

def main():
	#con = ssh(host='pwnable.kr',user='asm',password='guest',port=2222)
	#r = con.connect_remote('0',9007)
	r = remote('0',9007)
	print(r.recvuntil('- Ready? starting in 3 sec... -'))
	print( idd + "waiting...")

	#solve 100 coin problems
	for i in range(0,100):
		Solve(r)

	#print any text and flag the service gives us
	out = idd + 'geting output'
	while( out != '' ):
		print(out)
		out = r.recv(timeout=1)

	r.close()

def printf(format, *args):
	sys.stdout.write(format % args)

#solves the coin problem
def Solve(r):
	#get n and c
	r.recvuntil('N=')
	coins = int( r.recvuntil(' ') )
	r.recvuntil('C=')
	chances = int( r.recvuntil('\n') )
	printf(idd+"coins: %d chances:%d\n",coins,chances)

	#vars for binary search
	cmid = 0
	cmin = 0
	cmax = coins-1
	weight = 0
	count = 0
	goleft = True

	#split list in half and get weight of left half
	#if weight is divisable by 10, counter fit coin is amoung weighed coins
	#else counterfit coin is in right half of list
	while( count < chances ):
		if(cmin == cmax):
			printf(idd+"found coin %d\n", cmin)

		cmid = (cmax-cmin)/2 + cmin
		weight = GetWeight(r,cmin,cmid)
		goleft = ( (weight % 10) > 0 ) #is cointerfit coin in left half, then go left

		if( goleft ):
			cmax = cmid
		else:
			cmin = cmid + 1
		count += 1
	#send the element of the counterfit coin to service
	if(goleft):
		r.send(str(cmin) + '\n')
	else:
		r.send(str(cmax) + '\n')
	#set result from sercive
	print(r.recvline())

#sends indexes in range [cmin, cmax] and returns their weight
def GetWeight(r,cmin, cmax):
	sent = "" #string to send to service
	weight = 0

	for i in range(cmin, cmax+1):
		sent += str(i) + " "
	sent += '\n'

	r.send(sent)
	weight = int(r.recvline())
	printf(idd+"sent: %d to %d weight: %d\n",cmin, cmax, weight)
	return weight

if __name__ == "__main__":
	main()
