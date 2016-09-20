#!/usr/bin/python

import sys
from base64 import b64encode

print b64encode(sys.stdin.read())
