'''
Created on Dec 20, 2014

@author: gianko

Utility class that transforms RAW HTTP Requests into Guenther input format.

'''

import sys, StringIO
from BaseHTTPServer import BaseHTTPRequestHandler
import urlparse
import json


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, req):
        if isinstance(req, str):
            self.rfile = StringIO(req)
        else:
            self.rfile = req
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

def main(fin, https=False):
    request = HTTPRequest(fin)

    if request.error_code is None:
        json_req = {}
        json_req["method"] = request.command
        
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(request.path)
        
        if https:
            scheme = "https"
        else:
            scheme = "http"
        
        base = "{0}://{1}".format(scheme, request.headers['host'])
        
        json_req["urlp"] = urlparse.urljoin(base, path)    
        
        json_req["queryp"] = urlparse.parse_qs(query)
        
        """
        parse_qs returns a list of values for each query string param.
        We do not assume any corner case here and we take the first on.
        """
        for k,v in json_req["queryp"].iteritems():
            json_req["queryp"][k] = json_req["queryp"][k][0]
        
        json_req["bodyp"] = {}
        if "content-type" in request.headers:
            if "application/x-www-form-urlencoded" in request.headers["content-type"]:
                c_len = int(request.headers.getheader('content-length', 0))
                body = request.rfile.read(c_len)
                json_req["bodyp"] = urlparse.parse_qs(body)
                for k,v in json_req["bodyp"].iteritems():
                    json_req["bodyp"][k] = json_req["bodyp"][k][0]
        
        
        json_req["headers"] = dict(request.headers)
        if "content-length" in json_req["headers"]:
            del json_req["headers"]["content-length"]
        
        
        
        json.dump(json_req, sys.stdout, indent=True)
    else:
        sys.stderr.write("Error while parsing the request: {0}\n".format(request.error_message))

if __name__ == '__main__':
    https = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "-https":
            https = True
    sys.stderr.write("Using https {0}\n".format(https))
    main(sys.stdin, https=https)
            