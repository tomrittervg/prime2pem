#!/usr/bin/python

import sys
from Crypto.PublicKey import RSA

from prime2pemutils import RSAKey

if __name__ == "__main__":

    tests = ['test/512.key', 'test/1024.key', 'test/2048.key', 'test/4096.key']
    
    for t in tests:
        f = open(t)
        pem = f.read()
        k = RSA.importKey(pem)
        
        p = k.p
        q = k.q
        
        print "Testing", t
        
        newk = RSAKey(p, q)
        
        if k.p != newk.p or k.q != newk.q or k.n != newk.n or k.e != newk.e:
            print "Did not copy a basic parameter over: p, q, n, or e"
            sys.exit(1)
        if k.d != newk.d:
            print "Did not compute d correctly."
            sys.exit(1)
        if k.u != newk.u:
            print "Did not compute u correctly."
            sys.exit(1)
            
        newpem = newk.getPEM()
        if pem != newpem:
            print "Generated PEM did not match original PEM"
            sys.exit(1)
        print "Success"
