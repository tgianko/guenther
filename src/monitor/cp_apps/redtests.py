'''
Created on Oct 17, 2014

This is an open redirector service.


@author: gianko
'''

import cherrypy
from datetime import datetime

INDEX = """<html>
<head>

    <title>Redirection Test Service</title>
    <meta http-equiv="cache-control" content="max-age=0" />
    <meta http-equiv="cache-control" content="no-cache" />
    <meta http-equiv="expires" content="0" />
    <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
    <meta http-equiv="pragma" content="no-cache" />
</head>

    <body>
        <h1>JS Test Service</h1>
        
        <h3>Hello, human!</p>

    </body>

</html>"""

class OpenRedirectorService(object):
    '''
    classdocs
    '''

    db = []

    def get_req_id(self, params):
        req_id = params.get("req_id", None)
        return req_id

    def get_target(self, params):
        target = params.get("target", None)
        return target

    def store_req(self, req_id, method, qs, body):
        cherrypy.log("Storing redirection request req_id=%s" % (req_id))
        
        ts = datetime.now()
        request = {"method" : method, 
                   "url"    : cherrypy.url(), 
                   "qs"     : qs,
                   "body"   : body,
                   "headers": cherrypy.request.headers}
        
        cherrypy.log("cherrypy.request.headers=%s" % (cherrypy.request.headers))
        
        entry = (str(ts), req_id, request)
        OpenRedirectorService.db.append(entry)

    @cherrypy.expose
    def index(self, **qs):
        target = self.get_target(qs)
        if target is None:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = self.get_req_id(qs)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        
        self.store_req(req_id, method, qs, body)
        
        raise cherrypy.HTTPRedirect(target)
