'''
Created on Nov 5, 2014

@author: gianko
'''


from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

from datetime import datetime

class FTPSchemeDetectionHandler(FTPHandler):

    db = []

    def __init__(self, conn, server, ioloop=None):
        FTPHandler.__init__(self, conn, server, ioloop)

    def on_connect(self):
        ts = datetime.now()
        entry = ("(CONNECT)", str(ts), self.remote_ip, self.remote_port, ("", ""))
        FTPSchemeDetectionHandler.db.append(entry)

    def on_disconnect(self):
        ts = datetime.now()
        entry = ("(DISCONNECT)", str(ts), self.remote_ip, self.remote_port, ("", ""))
        FTPSchemeDetectionHandler.db.append(entry)
        
    def on_login(self, username):
        pass
        #print "%s:%s login %s" % (self.remote_ip, self.remote_port, username)

    def on_logout(self, username):
        pass
        #print "%s:%s logout %s" % (self.remote_ip, self.remote_port, username)

    def on_file_sent(self, file):
        pass
        #print "%s:%s file sent %s" % (self.remote_ip, self.remote_port, file)

    def on_file_received(self, file):
        pass
        #print "%s:%s file received %s" % (self.remote_ip, self.remote_port, file)

    def on_incomplete_file_sent(self, file):
        pass
        #print "%s:%s incomplete file sent %s" % (self.remote_ip, self.remote_port, file)

    def on_incomplete_file_received(self, file):
        self.log("%s:%s received incomplete file %s. Removing." % (self.remote_ip, self.remote_port, file))
        import os
        os.remove(file)

    def pre_process_command(self, line, cmd, arg):
        ts = datetime.now()
        
        entry = ("PRE", str(ts), self.remote_ip, self.remote_port, (line, None))

        FTPSchemeDetectionHandler.db.append(entry)
        
        FTPHandler.pre_process_command(self, line, cmd, arg)
        
    def process_command(self, cmd, *args, **kwargs):
        FTPHandler.process_command(self, cmd, *args, **kwargs)
        ts = datetime.now()
        last_response = None
        if self._last_response:
            last_response = self._last_response
            
        entry = ("POST", str(ts), self.remote_ip, self.remote_port, (cmd, last_response))
        FTPSchemeDetectionHandler.db.append(entry)

def main():
    authorizer = DummyAuthorizer()
    authorizer.add_anonymous("/opt/anonymous/", perm="lr")

    handler = FTPSchemeDetectionHandler
    handler.authorizer = authorizer
    server = FTPServer(('', 2121), handler)
    server.serve_forever()

if __name__ == "__main__":
    main()