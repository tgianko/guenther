'''
Created on Sep 30, 2014

This is an incomplete intentionally-vulnerable
web application.

@TODO: to be completed.

@author: gianko
'''
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import urlparse
import sys

import utils.log as log

import common
import httplib2

LOG = log.getdebuglogger("webapp")

HOST_NAME = "127.0.0.1"
PORT_NUMBER = 8080

TIMEOUT = 30

def handle_ssrf(self):
    """ @TODO: to be completed."""
    url = urlparse.urlparse(self.path)
    urlp = urlparse.urlparse(self.path)
    qs = urlparse.parse_qs(urlp.query)
    
    if "fetch" not in qs:
        self.serve_404()
        return
    
    fetch = qs["fetch"][0]
    
    http = httplib2.Http(disable_ssl_certificate_validation=True, timeout=TIMEOUT)
    
    response, content = http.request(fetch, "GET")
        
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", len(content))
    self.end_headers()
    self.wfile.write(content)


    

class WebApp(BaseHTTPRequestHandler):
    
    pylets = {"/": lambda s: handle_ssrf(s)
              }
    
    def do_GET(self):
        tname =  threading.currentThread().getName()
        url = urlparse.urlparse(self.path)
        LOG.info("%s, URL %s" % (tname, url))
        LOG.info("%s client_address=%s" % (tname, self.client_address))
        LOG.info("%s headers=%s" % (tname, self.headers))
        
        if url.path in WebApp.pylets:
            WebApp.pylets[url.path](self)
           
        else:
            LOG.info("404, Not serving")
            self.serve_404()

    def serve_200(self):
        LOG.info("200 OK")
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", len(common.OK_PAGE))
        self.end_headers()
        self.wfile.write(common.OK_PAGE)

    def serve_302(self):  
        LOG.info("302 OK")
        self.send_response(302)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-Length", len(common.REDIR_PAGE))
        self.send_header("Location", "/200")
        self.end_headers()
        self.wfile.write(common.REDIR_PAGE)

    def serve_404(self):  
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(common.ERROR_PAGE) 


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

def main(host, port):
    server_class = ThreadedHTTPServer
    httpd = server_class((host,port), WebApp)
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
