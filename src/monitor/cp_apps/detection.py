'''
Created on Oct 24, 2014

@author: gianko
'''

import cherrypy
from cherrypy.lib.static import serve_file
from datetime import datetime
import os

class DetectionService(object):
    
    db = []
    
    def __init__(self, staticdir=None):
        self.staticdir = staticdir
        if self.staticdir is None:
            self.staticdir = os.environ["BOMBSPATH"]
    
    #def __init__(self, db):
    #    self.db = db
    
    def get_req_id(self, params):
        req_id = params.get("req_id", None)
        return req_id
    
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
        DetectionService.db.append(entry)
    
    def handle_options(self):
        cherrypy.response.headers['Allow'] = "POST, GET"
    
    @cherrypy.expose
    def index(self, **qs):
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
                
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, method, qs, body)
        
        if method == "OPTIONS":
            self.handle_options()
            return ""
        else:
            return "%s with req_id=%s done." % (method, req_id)
    
    @cherrypy.expose
    def eicar(self, **qs):
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
                
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, method, qs, body)
        
        return """X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"""
    
    @cherrypy.expose
    def static(self, **qs):
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read()
        self.store_req(req_id, method, qs, body)
        
        ret = serve_file(os.path.join(self.staticdir, "1.png"))
        
        del cherrypy.response.headers["Last-Modified"]
        del cherrypy.response.headers["Content-Length"]
        
        cherrypy.response.headers["Content-Type"] = "text/plain; charset=utf-8"
        
        cherrypy.response.headers["Content-Disposition"] = "attachment;filename=nope.txt"
    
        cherrypy.response.headers["Content-Length"] = "-1"
        
        return ret
        
    @cherrypy.expose
    def virut(self, **qs):
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read()
        self.store_req(req_id, method, qs, body)
        
        ret = serve_file(os.path.join(self.staticdir, "0849110764b4e1d1f402104e722731ecffd35022efa32b330bf0c4d4f42bcf6a"))
        
        del cherrypy.response.headers["Last-Modified"]
        del cherrypy.response.headers["Content-Length"]
        
        cherrypy.response.headers["Content-Type"] = "application/x-msdownload"
        cherrypy.response.headers["Content-Disposition"] = "attachment;filename=clickonme.exe"

        
        return ret
        
    @cherrypy.expose
    def monello(self, **qs):
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
                
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, method, qs, body)
        
        if method == "OPTIONS":
            self.handle_options()
            return ""
        else:
            cherrypy.response.headers["Content-Type"] = "application/notexist"
            return "%s with req_id=%s done." % (method, req_id)