'''
Created on Oct 17, 2014

This is a cherrypy web service that implements tests to detect JS capabilities
of web browsers.


@author: gianko
'''

import cherrypy
from datetime import datetime
import utils
from time import sleep
import os
import urllib
import time

INDEX = """<html>
<head>

    <title>JS Test Service</title>
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

XMLHTTPREQ_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
XMLHttpRequest test
</title>

<script>
xmlhttp=new XMLHttpRequest();
xmlhttp.open("GET","{monitor}/ping?src=xmlhttpreq&req_id={req_id}",true);
xmlhttp.send();
</script>

</head>

<body>
<p>XMLHttpRequest test. Ping service {monitor}/ping?src=xmlhttpreq&req_id={req_id}</p>
<img src="{monitor}/slow_image?dur=5&req_id={req_id}"/>
</body>

</html>"""


IMAGE_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
Image test
</title>

<script>

img = new Image();
img.src = "{monitor}/ping?src=image&req_id={req_id}"

</script>

</head>

<body>
<p>Image test. Ping service {monitor}/ping?src=image&req_id={req_id}</p>
<img src="{monitor}/slow_image?dur=5&req_id={req_id}"/>
</body>

</html>"""


DUR_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
Duration test
</title>

<script>
var c = 0;
function ping() {{
  // Ping!
  img = new Image();
  img.src = "{monitor}/ping?req_id={req_id}&src=dur&n=" + c;
  c = c + 1;
}}

setInterval(ping, 1000)

</script>

</head>

<body>
<p>Duration test. Ping service {monitor}/ping?src=dur&req_id={req_id}</p>
<img src="{monitor}/slow_image?dur={duration}"/>
</body>

</html>"""

CROSSDOMAINREQ_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
Crossdomain test
</title>

<script>

xmlhttp=new XMLHttpRequest();
url = "{monitor}/ping?src=rec_crossdomain&req_id={req_id}";
xmlhttp.open("GET","https://images-onepick-opensocial.googleusercontent.com/gadgets/proxy?url=" + encodeURIComponent(url) + "&container=onepick&gadget=a" ,true);
xmlhttp.send();

</script>

</head>

<body>
<p>Cross-domain Test. Ping service {monitor}/ping?src=dur&req_id={req_id}</p>
<img src="{monitor}/slow_image?dur=5&req_id={req_id}"/>
<p>

</p>
</body>

</html>"""

BYPMAXCONN_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
Bypass Maximum Connection test.
</title>

<script>
for (var c=0; c < {max}; c++) {{
    var img = new Image();
    img.src = "{monitor}/{req_id}-" + c;
}}

</script>

</head>

<body>
<p>Bypass Maximum Connection test. Monitor {monitor}/{req_id}</p>
</body>

</html>"""

WEBWORKERS_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
WebWorker test
</title>

<script>

if(typeof(Worker) !== "undefined") {{
  img = new Image();
  img.src = "{monitor}/ping?req_id={req_id}&src=worker&result=yes";
}} else {{
  img = new Image();
  img.src = "{monitor}/ping?req_id={req_id}&src=worker&result=no";
}}

</script>

</head>

<body>
<p>WebWorker test. Ping service {monitor}/ping?src=image&req_id={req_id} ...</p>
<img src="{monitor}/slow_image?dur=2&req_id={req_id}"/>
</body>

</html>"""

DOSRECURSIVE_TEST = """<html>
<head>

<meta http-equiv="cache-control" content="max-age=0" />
<meta http-equiv="cache-control" content="no-cache" />
<meta http-equiv="expires" content="0" />
<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
<meta http-equiv="pragma" content="no-cache" />

<title>
Crossdomain test
</title>

<script>

function step2 () {{
  var ping = new Image();
  ping.src = "{monitor}/ping?src=AjaxDateReceived&req_id={req_id}&n=1";
  
  var html = this.responseText;
  var tk1= "<div class='alert alert-success' style='margin-top: 10px'><a href='"
  var tk2= "'>Click here to see this full height screenshot in a new tab.</a></div>"
  var newurl = html.split(tk1)[1].split(tk2)[0]
  console.log(newurl);
  var cor=new XMLHttpRequest();
  cor.open("GET","https://images-onepick-opensocial.googleusercontent.com/gadgets/proxy?url=" + encodeURIComponent(newurl) + "&container=onepick&gadget=a" ,true);
  cor.send();
  
  //var doc = new DOMParser().parseFromString(html, 'text/html');
  //imgs = doc.getElementsByTagName( 'img' );
  //for (i = 0; i < imgs.length; i++) {{
  //  console.log(imgs[i].src);
  //  if (imgs[i].src.indexOf("/v6/") > -1) {{
  //    console.log("found!");
  //    var cor=new XMLHttpRequest();
  //    cor.open("GET","https://images-onepick-opensocial.googleusercontent.com/gadgets/proxy?url=" + encodeURIComponent(imgs[i].src) + "&container=onepick&gadget=a" ,true);
  //    cor.send();
  //    break;
  //  }}
  //}}
}}


// POST request
var urlPing = "{monitor}/ping?src=dosrecursive&req_id={req_id}&n=3";
var urlBase = "https://www.url2png.com/?url=" + encodeURIComponent(urlPing);

var cor=new XMLHttpRequest();
cor.open("GET","https://images-onepick-opensocial.googleusercontent.com/gadgets/proxy?url=" + encodeURIComponent(urlBase) + "&container=onepick&gadget=a" ,true);
cor.onload = step2;
cor.send();

var ping = new Image();
ping.src = "{monitor}/ping?src=AjaxSent&req_id={req_id}&n=0";

</script>

</head>

<body>
<p>Cross-domain Test. Ping service {monitor}/ping?src=dur&req_id={req_id}</p>
<img src="{monitor}/slow_image?dur=30&req_id={req_id}"/>
<p>

</p>
</body>

</html>"""

class JSTestsService(object):
    '''
    classdocs
    '''
    db = []
    
    def __init__(self, staticdir=None):
        self.staticdir = staticdir
        if self.staticdir is None:
            self.staticdir = os.environ["BOMBSPATH"]

    def store_req(self, req_id, jstest, method, qs, body):
        cherrypy.log("Storing request req_id=%s" % (req_id))
        
        ts = time.time()
        request = {"method" : method, 
                   "url"    : cherrypy.url(), 
                   "qs"     : qs,
                   "body"   : body,
                   "headers": cherrypy.request.headers}
        
        cherrypy.log("cherrypy.request.headers=%s" % (cherrypy.request.headers))
        
        entry = (str(ts), req_id, jstest, request)
        JSTestsService.db.append(entry)

    @cherrypy.expose
    def index(self):
        return INDEX
    cherrypy.response
    index._cp_config = {'response.stream': True}
    
    @cherrypy.expose
    def xmlhttpreqtest(self,**qs):
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "XMLHTTPRequest", method, qs, body)
        
        return XMLHTTPREQ_TEST.format(monitor=mon, req_id=req_id)

    @cherrypy.expose
    def imagetest(self, **qs):
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "Image", method, qs, body)
        
        return IMAGE_TEST.format(monitor=mon, req_id=req_id)
        
    @cherrypy.expose
    def durtest(self, **qs):
        dur = qs.get("dur", 30)
        dur = int(dur)
        
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "Duration", method, qs, body)
        
        return DUR_TEST.format(monitor=mon, req_id=req_id, duration=dur)
        
    @cherrypy.expose
    def ping(self, **qs):
        src = qs.get("src", None)
        n = qs.get("n", None)
        req_id = qs.get("req_id", None)
        
        cherrypy.log(">>Ping<< req_id=%s, src=%s n=%s" % (req_id, src, n))
        
        method = cherrypy.request.method
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
            
        self.store_req(req_id, "Ping", method, qs, body)
        return "ping, req_id=%s, src=%s n=%s" % (req_id, src, n)

    @cherrypy.expose
    def sleep(self, **qs):
        dur = qs.get("dur", 1)
        dur = int(dur)
        src = qs.get("src", None)
        n = qs.get("n", None)
        req_id = qs.get("req_id", None)
        
        cherrypy.log(">>Sleep<< req_id=%s, src=%s n=%s" % (req_id, src, n))
        
        method = cherrypy.request.method
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
            
        self.store_req(req_id, "Sleep", method, qs, body)
        
        def shaper():
            sleep(1)
            yield "slow ping, req_id=%s, src=%s n=%s" % (req_id, src, n)
            
        return shaper()
    
    @cherrypy.expose
    def slow_image(self, **qs):
        dur = qs.get("dur", 30)
        dur = int(dur)
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "Slow Image", method, qs, body)
        
        cherrypy.response.headers["Content-type"] = "image/png" 
        cherrypy.response.headers["Pragma-directive"] = "no-cache"
        cherrypy.response.headers["Cache-directive"] = "no-cache"
        cherrypy.response.headers["Cache-control"] = "no-cache"
        cherrypy.response.headers["Pragma"] = "no-cache"
        cherrypy.response.headers["Expires"] = "0"
        
        def chunkit():
            f = open("%s/test_image.png" % self.staticdir, 'rb')
            img = f.read()
            f.close()
            avg = int(len(img)/dur)
            for i in xrange(0, len(img), avg):
                cherrypy.log("Sending piece %s:%s" % (i, i+avg))
                yield img[i:i+avg]
                
                sleep(1)

            
        return chunkit()
    
    @cherrypy.expose
    def crossdomaintest(self, **qs):
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "Cross-domain Test", method, qs, body)

        return CROSSDOMAINREQ_TEST.format(monitor=mon, req_id=req_id)    

    @cherrypy.expose
    def bypmaxconn(self, **qs):
        maxr = qs.get("max", 32)
        maxr = int(maxr)
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        
        method = cherrypy.request.method
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        
        self.store_req(req_id, "Bypass Max. Conn.", method, qs, body)
        return BYPMAXCONN_TEST.format(monitor=mon, req_id=req_id, max=maxr)

    @cherrypy.expose
    def webworker(self, **qs):
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        
        method = cherrypy.request.method
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        
        self.store_req(req_id, "Bypass Max. Conn.", method, qs, body)
        return WEBWORKERS_TEST.format(monitor=mon, req_id=req_id)
    
    
    
    """
    
    EXPERIMENTAL TESTS!!!!
    
    """

    @cherrypy.expose
    def restricted(self, **qs):
        cherrypy.response.headers["Access-Control-Allow-Origin"] = "http://mozilla.com" 
        return "This is restricted!"

    @cherrypy.expose
    def cookiereader(self, **qs):
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "cookiereader", method, qs, body)
        return "window.alert(document.cookie);"

    @cherrypy.expose
    def dosrecursive(self, **qs):
        mon = qs.get("mon", None)
        if mon is None or len(mon) == 0:
            raise cherrypy.HTTPError(404, "Not found")
        
        req_id = qs.get("req_id", None)
        method = cherrypy.request.method
        
        body = None
        if method.lower() == "post":
            body = cherrypy.request.body.read().encode("string-escape")
        self.store_req(req_id, "Cross-domain Test", method, qs, body)

        return DOSRECURSIVE_TEST.format(monitor=mon, req_id=req_id)  
