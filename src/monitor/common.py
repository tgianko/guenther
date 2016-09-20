'''
Created on Sep 10, 2014

@author: gianko
'''
from BaseHTTPServer import BaseHTTPRequestHandler
import threading
import urlparse

import utils.log as log

LOG = log.getdebuglogger("common")

def create_httpd(callback):
    
    class HTTPScanMonitor(BaseHTTPRequestHandler):
        
        def do_GET(self):
            tname =  threading.currentThread().getName()
            LOG.info("<%s> GET %s" % (tname, self.path))
            LOG.info("<%s> client_address=%s" % (tname, self.client_address))
            LOG.info("<%s> headers=%s" % (tname, self.headers))
            callback(self) 
        
    return HTTPScanMonitor         
    
def serve_302(self, f_location):
    self.send_response(302)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", 0)
    self.send_header("Location", f_location())
    self.end_headers()

OK_PAGE = """<html>
    <head>
        <title>200 - Page found</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>HTTPD Monitor</h2>
        
        <p>Well, this is actually a test page.</p>

    </body>
</html>
"""

REDIR_PAGE = """<html>
    <head>
        <title>302 - Redirection</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>HTTPD Monitor</h2>
        
        <p>If nothing happens, click <a href="/200">here</a> to go to the right page.</p>

    </body>
</html>
"""

ERROR_PAGE = """<html>
    <head>
        <title>404 - Page not found</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>HTTPD Monitor</h2>
        
        <p>Ooops! Something wrong is going on there.</p>

    </body>
</html>
"""


JSSUPP_XMLHTTPREQ = """<html>
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
xmlhttp.open("GET","%(monitor)s/ping",true);
xmlhttp.send();
</script>

</head>

<body>
<p>Test</p>
</body>

</html>"""

JSSUPP_IMG = """<html>
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
img.src = "%(monitor)s/ping"

</script>

</head>

<body>
<p>Test</p>
</body>

</html>"""

JSSUPP_DUR = """<html>
<head>
<title>
Duration test
</title>

<script>
var i = 1;
function callback() {
    xmlhttp=new XMLHttpRequest();
    xmlhttp.open("GET","%(monitor)s/ping" + i,true);
    xmlhttp.send();
    i = i + 1;
}

window.setInterval(callback, 0)

</script>

</head>

<body>
<p>Test</p>
</body>

</html>"""