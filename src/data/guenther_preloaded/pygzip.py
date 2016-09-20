#!/usr/bin/python

import StringIO, gzip, sys

def do_gzip(s, l=1):
    d = s
    i = 0
    while i < l:
        out = StringIO.StringIO()
        with gzip.GzipFile(fileobj=out, mode="w") as f:
            f.write(d)
        d = out.getvalue()
        out.close()
        i += 1
    return d

sys.stdout.write(do_gzip(sys.stdin.read()))
