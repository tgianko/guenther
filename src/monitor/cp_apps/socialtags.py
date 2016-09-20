'''
Created on Nov 5, 2014

@author: gianko
'''

import cherrypy
import json, gzip, cStringIO
from datetime import datetime

class SocialTagsService(object):
    
    db = {}
    
    def __init__(self):
        {'tools.gzip.on': True}
    
    #def __init__(self, db):
    #    self.db = db
    
    @cherrypy.expose
    def oembed(self, **argk):
        req_id = argk.get("req_id", None)
        cherrypy.log("Storing request req_id=%s" % (req_id))
        
        ts = datetime.now()
        request = (cherrypy.url(), 
               argk,
               cherrypy.request.headers)
        cherrypy.log("cherrypy.request.headers=%s" % (cherrypy.request.headers))
        
        entry = (str(ts), req_id, request)
        SocialTagsService.db.setdefault(req_id, entry)
        
        cherrypy.response.headers['Content-Type'] = "application/json"
        oembed = {
                "version": "1.0",
                "type": "link",
                "url": "http://130.83.162.219/detect"
                  }
        
        return json.dumps(oembed) 
    
    @cherrypy.expose
    def twittercard(self, **argk):
        req_id = argk.get("req_id", None)
        cherrypy.log("Storing request req_id=%s" % (req_id))
        
        ts = datetime.now()
        request = (cherrypy.url(), 
               argk,
               cherrypy.request.headers)
        cherrypy.log("cherrypy.request.headers=%s" % (cherrypy.request.headers))
        
        entry = (str(ts), req_id, request)
        SocialTagsService.db.setdefault(req_id, entry)
        
        cherrypy.response.headers['Content-Type'] = "text/html"
        #cherrypy.response.headers['Content-Encoding'] = "gzip"
        
        card = """<meta name="twitter:card" content="summary" />
<meta name="twitter:site" content="@flickr" />
<meta name="twitter:title" content="Small Island Developing States Photo Submission" />
<meta name="twitter:description" content="View the album on Flickr." />
<meta name="twitter:image" content="https://farm6.staticflickr.com/5510/14338202952_93595258ff_z.jpg" />
<meta name="twitter:url" content="http://deeds91.deeds.informatik.tu-darmstadt.de/detect" />"""

        #zbuf=cStringIO.StringIO()
        #zfile=gzip.GzipFile(mode='wb', fileobj=zbuf, compresslevel=9)
        #zfile.write(card)
        #zfile.close()


        return card