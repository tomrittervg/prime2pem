#!/usr/bin/python

# Much of this code was copy/pasted from PyCrypto, which was released into the 
#  public domain

import binascii, struct


def inverse(u, v):
    """inverse(u:long, v:long):long
    Return the inverse of u mod v.
    """
    u3, v3 = long(u), long(v)
    u1, v1 = 1L, 0L
    while v3 > 0:
        q=divmod(u3, v3)[0]
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1


class RSAKey:
    def __init__(self, p, q, e=0x10001):
        if q > p:
            tmp = p
            p = q
            q = tmp
        self.p = p
        self.q = q
        self.n = self.p*self.q
        self.phi = (self.p-1) * (self.q-1)
        self.e = e
        self.d = inverse(self.e, self.phi)
        self.dP = self.d % (self.p-1)
        self.dQ = self.d % (self.q-1)
        self.u = inverse(self.q, self.p)
    def getPEM(self):
        der = DerSequence()
        der[:] = [ 0, 
                   self.n, 
                   self.e, 
                   self.d, 
                   self.p, 
                   self.q,
                   self.dP,
                   self.dQ,
                   self.u ]
        
        pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        binaryKey = der.encode()
        chunks = [ binascii.b2a_base64(binaryKey[i:i+48]) for i in range(0, len(binaryKey), 48) ]
        pem += ''.join(chunks)
        pem += "-----END RSA PRIVATE KEY-----\n"
        return pem
    def printComponents(self):
        print "Public Components:"
        print "N:", self.n
        print "E:", self.e
        print "Private Components:"
        print "P:", self.p
        print "Q:", self.q
        print "D:", self.d
        print "Private CRT Components:"
        print "dP:", self.dP
        print "dQ:", self.dQ
        print "u:", self.u

class DerObject:
    typeTags = { 'SEQUENCE':'\x30', 'BIT STRING':'\x03', 'INTEGER':'\x02' }

    def __init__(self, ASN1Type=None):
        self.typeTag = self.typeTags.get(ASN1Type, ASN1Type)
        self.payload = ''
        
    def _lengthOctets(self, payloadLen):
        '''
        Return an octet string that is suitable for the BER/DER
        length element if the relevant payload is of the given
        size (in bytes).
        '''
        if payloadLen>127:
            encoding = long_to_bytes(payloadLen)
            return chr(len(encoding)+128) + encoding
        return chr(payloadLen)

    def encode(self):
        return self.typeTag + self._lengthOctets(len(self.payload)) + self.payload	
    
    def _decodeLen(self, idx, str):
        '''
        Given a string and an index to a DER LV,
        this function returns a tuple with the length of V
        and an index to the first byte of it.
        '''
        length = ord(str[idx])
        if length<=127:
            return (length,idx+1)
        else:
            payloadLength = bytes_to_long(str[idx+1:idx+1+(length & 0x7F)])
            if payloadLength<=127:
                raise ValueError("Not a DER length tag.")
            return (payloadLength, idx+1+(length & 0x7F))

	def decode(self, input, noLeftOvers=0):
            try:
                self.typeTag = input[0]
                if (ord(self.typeTag) & 0x1F)==0x1F:
                    raise ValueError("Unsupported DER tag")
                (length,idx) = self._decodeLen(1,input)
                if noLeftOvers and len(input) != (idx+length):
                    raise ValueError("Not a DER structure")
                self.payload = input[idx:idx+length]
            except IndexError:
                raise ValueError("Not a valid DER SEQUENCE.")
            return idx+length

class DerInteger(DerObject):
    def __init__(self, value = 0):
        DerObject.__init__(self, 'INTEGER')
        self.value = value

    def encode(self):
        self.payload = long_to_bytes(self.value)
        if ord(self.payload[0])>127:
            self.payload = '\x00' + self.payload
        return DerObject.encode(self)

    def decode(self, input, noLeftOvers=0):
        tlvLength = DerObject.decode(self, input,noLeftOvers)
        if ord(self.payload[0])>127:
            raise ValueError ("Negative INTEGER.")
        self.value = bytes_to_long(self.payload)
        return tlvLength
				
class DerSequence(DerObject):
    def __init__(self):
        DerObject.__init__(self, 'SEQUENCE')
        self._seq = []
    def __delitem__(self, n):
        del self._seq[n]
    def __getitem__(self, n):
        return self._seq[n]
    def __setitem__(self, key, value):
        self._seq[key] = value	
    def __setslice__(self,i,j,sequence):
        self._seq[i:j] = sequence
    def __delslice__(self,i,j):
        del self._seq[i:j]
    def __getslice__(self, i, j):
        return self._seq[max(0, i):max(0, j)]
    def __len__(self):
        return len(self._seq)
    def append(self, item):
        return self._seq.append(item)

    def hasOnlyInts(self):
        if not self._seq: return 0
        test = 0
        for item in self._seq:
            try:
                test += item
            except TypeError:
                return 0
        return 1

    def encode(self):
        '''
        Return the DER encoding for the ASN.1 SEQUENCE containing
        the non-negative integers and longs added to this object.
        '''
        self.payload = ''
        for item in self._seq:
            try:
                self.payload += item
            except:
                try:
                    self.payload += DerInteger(item).encode()
                except:
                    raise ValueError("Trying to DER encode an unknown object")
        return DerObject.encode(self)

    def decode(self, input,noLeftOvers=0):
        '''
        This function decodes the given string into a sequence of
        ASN.1 objects. Yet, we only know about unsigned INTEGERs.
        Any other type is stored as its rough TLV. In the latter
        case, the correctectness of the TLV is not checked.
        '''
        self._seq = []
        try:
            tlvLength = DerObject.decode(self, input,noLeftOvers)
            if self.typeTag!=self.typeTags['SEQUENCE']:
                raise ValueError("Not a DER SEQUENCE.")
            # Scan one TLV at once
            idx = 0
            while idx<len(self.payload):
                typeTag = self.payload[idx]
                if typeTag==self.typeTags['INTEGER']:
                    newInteger = DerInteger()
                    idx += newInteger.decode(self.payload[idx:])
                    self._seq.append(newInteger.value)
                else:
                    itemLen,itemIdx = self._decodeLen(idx+1,self.payload)
                    self._seq.append(self.payload[idx:itemIdx+itemLen])
                    idx = itemIdx + itemLen
        except IndexError:
            raise ValueError("Not a valid DER SEQUENCE.")
        return tlvLength

def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s


def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc
