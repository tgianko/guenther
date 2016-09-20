'''
Created on Sep 10, 2014

@author: gianko
'''

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import urlparse
import sys

import utils.log as log

import monitor.common as common

LOG = log.getdebuglogger("httpdmon")
HOST_NAME = "127.0.0.1"
MONITOR = "127.0.0.1"
PORT_NUMBER = 8080

def get_jssupp_xmlhttpreq(self):
    page = common.JSSUPP_XMLHTTPREQ % {"monitor": "http://%s:%s" % (MONITOR, PORT_NUMBER)}
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", len(page))
    self.end_headers()
    self.wfile.write(page)
    
def get_jssupp_img(self):
    page = common.JSSUPP_IMG % {"monitor": "http://%s:%s" % (MONITOR, PORT_NUMBER)}
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", len(page))
    self.end_headers()
    self.wfile.write(page)

def get_jssupp_dur(self):
    page = common.JSSUPP_DUR % {"monitor": "http://%s:%s" % (MONITOR, PORT_NUMBER)}
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", len(page))
    self.end_headers()
    self.wfile.write(page)

def handle_ping(self):
    page = "Piiiiing"
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", len(page))
    self.end_headers()
    self.wfile.write(page)

    

    

class HttpdMonitor(BaseHTTPRequestHandler):
    
    pylets = {"/": lambda s: s.serve_200(),
              "/200": lambda s: s.serve_200(),
              "/30x": lambda s: s.serve_302(),
              "/ping/getpage/xmlhttpreq": lambda s: get_jssupp_xmlhttpreq(s),
              "/ping/getpage/img": lambda s: get_jssupp_img(s),
              "/dur/getpage/xmlhttpreq": lambda s: get_jssupp_dur(s),
              "/ping": lambda s: handle_ping(s),
              }
    
    def do_GET(self):
        tname =  threading.currentThread().getName()
        url = urlparse.urlparse(self.path)
        LOG.info("%s, URL %s" % (tname, url))
        LOG.info("%s client_address=%s" % (tname, self.client_address))
        LOG.info("%s headers=%s" % (tname, self.headers))
        
        if url.path in HttpdMonitor.pylets:
            HttpdMonitor.pylets[url.path](self)
           
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
    httpd = server_class((host,port), HttpdMonitor)
    LOG.info("Server Starts - %s:%s" % (host,port))
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    
    LOG.info("Server Stops - %s:%s" % (host,port))  

if __name__ == '__main__':

    if len(sys.argv) == 4:
        HOST_NAME = sys.argv[1]
        PORT_NUMBER = int(sys.argv[2])
        MONITOR = sys.argv[3]

    main(HOST_NAME, PORT_NUMBER)
