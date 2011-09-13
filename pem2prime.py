#!/usr/bin/python

import sys
from prime2pemutils import RSAKey
from Crypto.PublicKey import RSA

def pemFileToObj(filename):
    f = open(filename)
    pem = f.read()
    
    r = RSA.importKey(pem)
    newkey = RSAKey(r.p, r.q, r.e)
    return newkey

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage:", sys.argv[0], " pemFile"
        sys.exit(1)

    key = pemFileToObj(sys.argv[1])
    key.printComponents()
