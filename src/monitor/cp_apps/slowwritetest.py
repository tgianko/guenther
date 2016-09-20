'''
Created on Oct 20, 2014

@author: gianko
'''

import cherrypy
from time import sleep

PART_1 = """<html>
<head>

    <title>SlowWrite Service</title>
    <meta http-equiv="cache-control" content="max-age=0" />
    <meta http-equiv="cache-control" content="no-cache" />
    <meta http-equiv="expires" content="0" />
    <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
    <meta http-equiv="pragma" content="no-cache" />
</head>

    <body><p>"""
    
PART_2 = """</p></body></html> """

SLOW_MSG = ["I", " am", " very", " slow!", "</p><p>"]

class SlowWriteService(object):
    '''
    classdocs
    '''
    

    @cherrypy.expose
    def index(self, dur=30):
        dur = int(dur)
        def shaper():
            cherrypy.log("Sending part 1")
            yield PART_1
            
            for i in range(0, dur):
                cherrypy.log("Sending %s" % SLOW_MSG[i%len(SLOW_MSG)])
                yield SLOW_MSG[i%len(SLOW_MSG)]
                sleep(1)
            
            yield PART_2
            
        return shaper()
    
    index._cp_config = {'response.stream': True}