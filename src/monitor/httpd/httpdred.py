'''
Created on Sep 10, 2014

This is a web server redirects user-agents 
to the URL passed with the query string target=

Example: 

http://HOST_NAME:PORT_NUMBER/?target=NEW_URL
produces an HTTP 302 with location NEW_URL

@author: gianko
'''

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import urlparse
import sys

import utils.log as log

import common

LOG = log.getdebuglogger("httpdred")

HOST_NAME = "127.0.0.1"
PORT_NUMBER = 80

class HttpdRed(BaseHTTPRequestHandler):
    
    def do_GET(self):
        tname =  threading.currentThread().getName()
        LOG.info("<%s> URL %s" % (tname, self.path))
        LOG.info("<%s> client_address=%s" % (tname, self.client_address))
        LOG.debug("<%s> headers=%s" % (tname, self.headers))
        
        urlp = urlparse.urlparse(self.path)
        qs = urlparse.parse_qs(urlp.query)
        
        if "target" not in qs:
            self.serve_404()
            return
        
        target = qs["target"][0]
        LOG.info("<%s> Redirecting to target: %s" % (tname, target))
                  
        self.send_response(302)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", 0)#len(common.REDIR_PAGE))       
        self.send_header("Location", target)
        self.end_headers()
        
    def serve_404(self):  
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(common.ERROR_PAGE) 


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(host, port):
    server_class = ThreadedHTTPServer
    httpd = server_class((host,port), HttpdRed)
    
    LOG.info("Server Starts - %s:%s" % (host,port))
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    
    LOG.info("Server Stops - %s:%s" % (host,port))  

if __name__ == '__main__':
    if len(sys.argv) == 3:
        main(sys.argv[1], int(sys.argv[2]))
    else:
        main(HOST_NAME, PORT_NUMBER)
    exit(0)