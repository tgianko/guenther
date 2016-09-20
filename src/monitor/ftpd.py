'''
Created on Sep 11, 2014

This is a fully-fledged FTPD.

@author: gianko
'''
import pyftpdlib.log
import logging
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import sys

HOST_NAME   = "127.0.0.1"
PORT_NUMBER = 21

def main(host, port):
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous("/opt/anonymous/", perm="lr")
   
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.banner = "ftpd ready."
    
    """ Add the port numbers here """
    handler.passive_ports = [2122]
    
    pyftpdlib.log.LEVEL = logging.DEBUG

    address = (host, port)
    server = FTPServer(address, handler)

    server.max_cons = 128
    server.max_cons_per_ip = 0

    """ Uncomment this line to disable support for PASV """
    #del handler.proto_cmds['PASV']

    server.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) == 3:
        main(sys.argv[1], int(sys.argv[2]))
    else:
        main(HOST_NAME, PORT_NUMBER)