#!/usr/bin/python

import sys
from prime2pemutils import RSAKey

p = 0
q = 0
e = 0x10001

if __name__ == "__main__":
	if p == 0 or q == 0:
		print "Error: You need to set p and q in the code before running this"
		sys.exit(1)
	
	r = RSAKey(p, q)
	print r.getPEM()

