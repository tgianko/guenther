'''
Created on Oct 6, 2012

@author: gianko
'''
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import urlparse
import sys

import utils.log as log
import time

LOG = None


INFINITE_PAGE = """<html>
    <head>
        <title>Haloooooo</title>
        <meta http-equiv="PRAGMA" content="NO-CACHE"/>
    </head>
    <body>
        <h2>kabooom httpd</h2>
       
        <h3>Denial-of-Service tests for HTTP client</h3>
        
        <p>Halloooo to you.</p>
    </body>
</html>
"""

class InfiniteHeadersServer(BaseHTTPRequestHandler):
    
    def do_GET(self):
        tname =  threading.currentThread().getName()
        url = urlparse.urlparse(self.path)

        qs = urlparse.parse_qs(url.query)
        n = qs.get("n", ["0"])[0]
        n = int(n)

        s = qs.get("s", ["0"])[0]
        s = int(s)
        
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", len(INFINITE_PAGE))
        

        #var = "X" * s
        for i in range(0, n):
            for j in range(0, s):
                self.wfile.write("X")
            self.wfile.write("%s: test\r\n" % i)
            #self.send_header("%s%s" %(var, i), i)

        #self.send_header("a" * n, "a")
        
        LOG.info("%s, Just sent %s useless headers" % (tname, n))
        self.end_headers()
        self.wfile.write(INFINITE_PAGE)
        LOG.info("Done")
        

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main():
    global LOG
    LOG = log.getdebuglogger("headershttpd")
    HOST_NAME = "127.0.0.1"
    PORT_NUMBER = 8080
    
    if len(sys.argv) == 3:
        HOST_NAME = sys.argv[1]
        PORT_NUMBER = int(sys.argv[2])
    
    server_class = ThreadedHTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), InfiniteHeadersServer)
    LOG.info("Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER))
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == '__main__':
    main()