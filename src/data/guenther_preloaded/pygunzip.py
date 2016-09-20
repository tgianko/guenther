#!/usr/bin/python

import StringIO, gzip, sys

def do_gunzip(s):
    out = StringIO.StringIO(s)
    with gzip.GzipFile(fileobj=out, mode="r") as f:
        d = f.read()
    out.close()
    return d

sys.stdout.write(do_gunzip(sys.stdin.read()))
