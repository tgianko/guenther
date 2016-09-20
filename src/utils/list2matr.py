'''
Created on Jan 26, 2015

@author: gianko
'''

import sys, csv

b_map = {
         "b1": 3,
         "b2": 4,
         "b3": 5,
         "b4": 6,
         "b5": 7,
         "b6": 8,
         "b7": 9,
         "b8": 10,
         }

if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as csvfile:
        r = csv.reader(csvfile, delimiter=';')
        w = csv.writer(sys.stdout, csvfile, delimiter=';')
        buff = []
        for row in r:
            buff = [row[0], row[1], row[2], "", "", "", "", "", "", "", ""]
            behavs = row[3]
            for b in behavs.split(","):
                buff[b_map[b]] = "1"
        
            w.writerow(buff)