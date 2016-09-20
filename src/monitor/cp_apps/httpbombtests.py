'''
Created on Oct 20, 2014

This is the cherrypy application that tests a browsers
against multi-layered compressed HTML responses.

Parameters:

- s = int. The size of the uncompressed payload, size = 2^s
- g = int. Number of compression layers.


@author: gianko
'''

import cherrypy
import utils.io
from datetime import datetime
import os

class HtmlBombService(object):

    db = []
    
    def store_req(self, req_id, method, qs, body):
        cherrypy.log("Storing request req_id=%s" % (req_id))
        
        ts = datetime.now()
        request = {"method" : method, 
                   "url"    : cherrypy.url(), 
                   "qs"     : qs,
                   "body"   : body,
                   "headers": cherrypy.request.headers}
        
        cherrypy.log("cherrypy.request.headers=%s" % (cherrypy.request.headers))
        
        entry = (str(ts), req_id, request)
        HtmlBombService.db.append(entry)
    
    def __init__(self, staticdir=None):
        self.staticdir = staticdir
        if self.staticdir is None:
            self.staticdir = os.environ["BOMBSPATH"]
    
    @cherrypy.expose
    def gzipbomb(self, **qs):
        g = int(qs.get("g", 1))
        s = int(qs.get("s", 16))

        if not (g in range(0, 4) and s in range(16, 35)):
            cherrypy.log("Parameters s=%s g=%s out of range" % (s, g))
            raise cherrypy.HTTPError(400, "Parameters s=%s g=%s out of range" % (s, g))

        req_id = qs.get("req_id", None)
        method = cherrypy.request.method

        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, method, qs, body)
    
        data = utils.io.read_from_file("%s/html%sbit%s" % (self.staticdir, s, ".gz" * g))
        cherrypy.response.headers["Content-type"] = "text/html" 
        cherrypy.response.headers["Content-Encoding"] = str("gzip " * g)[0:-1]
        return data
