'''
Created on Jan 13, 2015

@author: gianko
'''

import sys

if __name__ == '__main__':
    f = open(sys.argv[1], 'r')
    out = [f.readline().split(" ")[1]]
    f.readline() # skip
    out += [l.split(";")[1].strip() for l in f.readlines()]
    print ";".join(out)
        