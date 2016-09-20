'''
Created on Oct 5, 2012

@author: gianko
'''
from base64 import b64encode, b64decode
from urllib import unquote_plus, quote_plus
from zlib import decompress, compress
import sys

def read_from_file(fname):
    f = open(fname, 'r')
    data = f.read()
    f.close()
    return data

def b64enc(s):
#    return str(b64encode(s), encoding="utf-8")
    return b64encode(s)

def b64dec(s):
#    if isinstance(s, str):
#        s = bytes(s, encoding="utf-8")
    return b64decode(s)

def urlenc(s):
    return quote_plus(s)

def urldec(s):
#    if not isinstance(s, str):
#        s = str(s, encoding="utf-8")
    return unquote_plus(s)

def inflate(s):
    return decompress(s, -15) 

def deflate(s):
    return compress(s)[2:-4]

def b64dec_inflate(s):
    plain = b64dec(s)
    return decompress(plain, -15)        # correction to handle inflate algorithm

def b64enc_deflate(s):
#    if not isinstance(s, bytes):
#        s = bytes(s, encoding="utf-8")
    return b64enc(compress(s)[2:-4])        # correction to handle deflate algorithm

def decode(data):
    dec = urldec(data)
    dec = b64dec_inflate(dec)
    print dec

def encode(data):
    enc = b64enc_deflate(data)
    enc = urlenc(enc)
    return enc

if __name__ == '__main__':
    command = sys.argv[1]
    alg = sys.argv[2]
    file = sys.argv[3]
    data = read_from_file(file)
    if command == "dec":
        if alg == "deflate":
            sys.stdout.write(deflate(data))
        elif alg == "urlenc":
            sys.stdout.write(urlenc(data))
        elif alg == "saml":
            sys.stdout.write(decode(data))
    elif command == "enc":
        if alg == "deflate":
            sys.stdout.write(inflate(data))
        elif alg == "urlenc":
            sys.stdout.write(urldec(data))
        elif alg == "saml":
            sys.stdout.write(encode(data))