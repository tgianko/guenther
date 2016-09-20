#!/usr/bin/python2.7
# encoding: utf-8
'''
guenther -- Test suite for SSR abuse detection

guenther is a set of security tests to detect SSR abuses

@author:     gianko

@copyright:  2016 Giancarlo Pellegrino. All rights deserved.

@license:    Apache License 2.0, see http://www.apache.org/licenses/LICENSE-2.0.html

@contact:    gpellegrino@trouge.net
@deffield    updated: Updated
'''

import sys, os, json, socket, time
from datetime import datetime

import hashlib
from pyftpdlib.authorizers import DummyAuthorizer
from monitor.pyftpdhandlers.ftpdetection import FTPSchemeDetectionHandler
from pyftpdlib.servers import FTPServer
from threading import Thread
import SocketServer
import argparse
import tempfile
import shutil
from __builtin__ import bytearray
import binascii
import string
from monitor.cp_apps.sctests import SideChannelService
import itertools
import csv
import httplib2
import base64
from monitor.cp_apps.httpbombtests import HtmlBombService
httplib2.RETRIES = 1

import iptc
import utils.log, utils.math, utils.pynetstat

from argparse import ArgumentParser, RawDescriptionHelpFormatter, FileType
from urllib import urlencode

import StringIO
import gzip


import cherrypy

#Servers are global except CherryPy which is reachable via the
#cherrypy package.
ftpserver = None
tcp_log_server = None 
sc_passive_tcp_server = None
sc_active_tcp_server = None
netstat_monitor = None

from monitor.cp_apps.redtests import OpenRedirectorService
from monitor.cp_apps.detection import DetectionService
from monitor.cp_apps.jstests import JSTestsService

__all__     = []
__version__ = 0.1
__date__    = '2014-10-24'
__updated__ = '2014-10-24'

args = None

MONITOR_DEFAULT_PORT = 80
MONITOR_DEFAULT_HOST = "localhost"
_MONITOR_IS_RUNNING = False

FQDN_TEST         = "FQDN"
IP_TEST           = "IPadr"
PORT_TEST         = "PORT"
SCHEME_TEST       = "SCHEME"
REDIR_TEST        = "RED"
POST_TEST         = "POST"
COMPR_TEST        = "BOMB"
JSAJAX_TEST       = "JSAJAX"
JSIMAGE_TEST      = "JSIMAGE_TEST"
JSDUR_TEST        = "JSDUR_TEST"
JSCROSS_TEST      = "JSCROSS_TEST"
JSBYPMAXCONN_TEST = "JSBYPMAXCONN_TEST"
JSWORKER_TEST     = "JSWORKER_TEST"
SC_TEST           = "SC_TEST"
HD_TEST           = "HD_TEST"
FETCH_TEST        = "FETCH_TEST"
FETCHCOMPR_TEST   = "FCOMPR_TEST"

PORT_TEST_DEFAULT = 8099
SCHEME_TEST_DEFAULT = "ftp"

# from /etc/service
SCHEME_TO_PORT = {
                  "ftp"    :   21,
                  "gopher" :   70,
                  "http"   :   80,
                  "ldap"   :  389,
                  "https"  :  443,
                  "dict"   : 2628,
                  }


rule = None
DEFAULT_SERVER_WAIT      = 15
SC_N_SCANS               = 5
SC_CLOSED_RST_DEFAULT    = "81"
SC_CLOSED_DROP_DEFAULT   = "82"
SC_OPEN_BIN_PASSIVE_PORT = "83"
SC_OPEN_BIN_ACTIVE_PORT  = "84"
SC_UNREACH_HOST          = "193.55.114.25"

DEBUG   = 0 
TESTRUN = 0
PROFILE = 0

log = utils.log.getdebuglogger("guenther")

"""
Preloaded gzip bombs with 1, 2, and 3 of compression levels. Stored in base64.
"""

preloaded_bombs = {
                   # plain: "testtest"
                   1: """H4sIAA2DhVQAAytJLS4pAWIAMbtp7AgAAAA=""",
                   2: """H4sIABqDhVQAA5Pv5mCQam4NYWDW9tTV02RMYjDcnfmGg4GBAQAlvQ4CGgAAAA==""",
                   3: """H4sIACWDhVQAA5Pv5mBQbW4NYWCe/P5ZQkBuHm9iwrVvV65eTvFJMrgz92dbc2MjI8Pz2j//pRgYGABiDwCXLgAAAA=="""
                   }

"""
  TODO: refactor. Move these declarations in common.csa
  Side Channel Analysis constant and maps

"""
"""
PORT SCANNING STATUS
"""
SCA_STATUS_P_CLOSED   = 1
SCA_STATUS_P_FILTERED = 2
SCA_STATUS_P_OPEN     = 3

"""
HOST DISCOVERY
"""
SCA_STATUS_H_ONLINE = 10
SCA_STATUS_H_OFFLINE = 20

"""
APP FINGERPRINT
"""
SCA_STATUS_R_EXIST         = 100
SCA_STATUS_R_NON_EXIST_404 = 200
SCA_STATUS_R_NON_EXIST     = 300

labels = {
          1: "P_CLOSED",
          2: "P_FILTERED",
          3: "P_OPEN",
          
          10: "H_ONLINE",
          20: "H_OFFLINE",
          
          100: "R_EXIST",
          200: "R_NEXISTS_404",
          300: "R_NEXISTS"
          }

b_map = {
         "b1": [SCA_STATUS_P_CLOSED, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
         "b2": [SCA_STATUS_P_FILTERED, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
         "b3": [SCA_STATUS_P_OPEN, SCA_STATUS_R_EXIST, SCA_STATUS_H_ONLINE],
         "b4": [SCA_STATUS_P_OPEN, SCA_STATUS_R_EXIST, SCA_STATUS_H_ONLINE],
         "b5": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST_404, SCA_STATUS_H_ONLINE],
         "b6": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
         "b7": [SCA_STATUS_P_OPEN, SCA_STATUS_R_NON_EXIST, SCA_STATUS_H_ONLINE],
         "b8": [SCA_STATUS_H_OFFLINE]
        }


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def norm_dict(d):
    return dict((k.lower(), v) for k, v in d.iteritems())

def create_request_from_json(s):
    req_data = json.loads(s)

    server_req_data = RequestData()
    server_req_data.method = req_data.get("method", "GET")
    server_req_data.urlp = req_data["urlp"]
    server_req_data.queryp = req_data.get("queryp", {})
    server_req_data.headers = norm_dict(req_data.get("headers", {}))
    server_req_data.bodyp = req_data.get("bodyp", {})
    
    return server_req_data

def set_monitor_url(req_data, url):
    matches = {
               "monitor"    : url,
               "monitor_b64": base64.urlsafe_b64encode(url)
               }
    req_data.replace(matches)
    return req_data

class RequestData():
    
    def __init__(self):
        self.method  = None
        self.url     = None
        self.urlp    = None
        self.headers = None
        self.query   = None
        self.queryp  = None
        self.body    = None
        self.bodyp   = None
    
    def replace(self, matches):
    
        """
        Replace all matches in the URL, if any.
        """
        self.url = self.urlp.format(**matches)
        
        """
        Copy and replace all matches in the query string and HTTP body, if any
        """
        self.query = None
        if self.queryp is not None:
            self.query = {}
            for p, v in self.queryp.items():
                p_form = p.format(**matches)
                v_form = v.format(**matches)
                self.query[p_form] = v_form
                
            self.query = urlencode(self.query)
        
        if self.method.lower() == "post" and "content-type" in self.headers:
            if "application/x-www-form-urlencoded" in self.headers["content-type"]:
                self.body = None
                if self.bodyp is not None:
                    self.body = {}
                    for p, v in self.bodyp.items():
                        p_form = p.format(**matches)
                        v_form = v.format(**matches)
                        self.body[p_form] = v_form
                        
                    self.body = urlencode(self.body)
            else:
                if self.bodyp is not None and isinstance(self.bodyp, str):
                    self.body = self.bodyp.format(**matches)
                    
        
    def to_dict(self):
        return {"method" : self.method,
                "urlp"   : self.urlp,
                "url"    : self.url,
                "queryp" : self.queryp,
                "query"  : self.query,
                "headers": self.headers,
                "body"   : self.body,
                "bodyp"  : self.bodyp
                }
    
    def __repr__(self):
        return str(self.to_dict())

import threading

class FTPDMonitorThread(threading.Thread):

    def __init__(self, ip, port, homedir):
        super(FTPDMonitorThread, self).__init__(target=self._start)
        self.ip = ip
        self.port = port
        self.homedir = homedir
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()
        
    def _start(self):
        authorizer = DummyAuthorizer()
        authorizer.add_anonymous(self.homedir, perm="lre")
    
        handler = FTPSchemeDetectionHandler
        handler.authorizer = authorizer
        
        if args.verbose < 1:
            def log(self, msg, logfun=None):
                pass
            handler.log = log
        
        server = FTPServer((self.ip, self.port), handler)
        
        while not self.stopped(): 
            server.serve_forever(timeout=1, blocking=False, handle_exit=False) 
        
        server.close_all()

    def stopped(self):
        return self._stop.isSet()

class ThreadedTCPRequestLogHandler(SocketServer.BaseRequestHandler):

    db = []

    def handle(self):
        #cur_thread = threading.current_thread()
        ts = str(datetime.now())
        data = self.request.recv(2048)           
        entry = (ts, self.client_address, data)
        ThreadedTCPRequestLogHandler.db.append(entry)

class ThreadedPassiveTCPRequestHandler(SocketServer.BaseRequestHandler):
    
    def handle(self):
        if args.verbose > 0:
            log.debug("ThreadedPassiveTCPRequestHandler: incoming connection. I will just sleep here for % seconds." % DEFAULT_SERVER_WAIT)
        time.sleep(DEFAULT_SERVER_WAIT)
        if args.verbose > 0:
            log.debug("ThreadedPassiveTCPRequestHandler: closing connection")


class ThreadedActiveTCPRequestHandler(SocketServer.BaseRequestHandler):
  
    banner = bytearray([0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d, 
                   0x4f, 0x70, 0x65, 0x6e, 0x53, 0x53, 0x48, 0x5f, 
                   0x36, 0x2e, 0x30, 0x70, 0x31, 0x20, 0x44, 0x65, 
                   0x62, 0x69, 0x61, 0x6e, 0x2d, 0x34, 0x2b, 0x64, 
                   0x65, 0x62, 0x37, 0x75, 0x32, 0x0d, 0x0a,
                   0x00, 0x00, 0x03, 0xbc, 0x05, 0x14, 0x03, 0xe5, 
                   0xa3, 0x19, 0x52, 0x14, 0x84, 0xfd, 0xc9, 0xc3, 
                   0x5a, 0x6d, 0x95, 0xe9, 0xfd, 0x95, 0x00, 0x00, 
                   0x00, 0xb7, 0x65, 0x63, 0x64, 0x68, 0x2d, 0x73, 
                   0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 
                   0x70, 0x32, 0x35, 0x36, 0x2c, 0x65, 0x63, 0x64, 
                   0x68, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 
                   0x69, 0x73, 0x74, 0x70, 0x33, 0x38, 0x34, 0x2c, 
                   0x65, 0x63, 0x64, 0x68, 0x2d, 0x73, 0x68, 0x61, 
                   0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x35, 
                   0x32, 0x31, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 
                   0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 
                   0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2d, 
                   0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 
                   0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x2c, 
                   0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 
                   0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 
                   0x72, 0x6f, 0x75, 0x70, 0x2d, 0x65, 0x78, 0x63, 
                   0x68, 0x61, 0x6e, 0x67, 0x65, 0x2d, 0x73, 0x68, 
                   0x61, 0x31, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 
                   0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 
                   0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 
                   0x34, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x2c, 0x64, 
                   0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 
                   0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 
                   0x6f, 0x75, 0x70, 0x31, 0x2d, 0x73, 0x68, 0x61, 
                   0x31, 0x00, 0x00, 0x00, 0x0f, 0x73, 0x73, 0x68, 
                   0x2d, 0x72, 0x73, 0x61, 0x2c, 0x73, 0x73, 0x68, 
                   0x2d, 0x64, 0x73, 0x73, 0x00, 0x00, 0x00, 0x9d, 
                   0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63, 
                   0x74, 0x72, 0x2c, 0x61, 0x65, 0x73, 0x31, 0x39, 
                   0x32, 0x2d, 0x63, 0x74, 0x72, 0x2c, 0x61, 0x65, 
                   0x73, 0x32, 0x35, 0x36, 0x2d, 0x63, 0x74, 0x72, 
                   0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f, 0x75, 0x72, 
                   0x32, 0x35, 0x36, 0x2c, 0x61, 0x72, 0x63, 0x66, 
                   0x6f, 0x75, 0x72, 0x31, 0x32, 0x38, 0x2c, 0x61, 
                   0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63, 0x62, 
                   0x63, 0x2c, 0x33, 0x64, 0x65, 0x73, 0x2d, 0x63, 
                   0x62, 0x63, 0x2c, 0x62, 0x6c, 0x6f, 0x77, 0x66, 
                   0x69, 0x73, 0x68, 0x2d, 0x63, 0x62, 0x63, 0x2c, 
                   0x63, 0x61, 0x73, 0x74, 0x31, 0x32, 0x38, 0x2d, 
                   0x63, 0x62, 0x63, 0x2c, 0x61, 0x65, 0x73, 0x31, 
                   0x39, 0x32, 0x2d, 0x63, 0x62, 0x63, 0x2c, 0x61, 
                   0x65, 0x73, 0x32, 0x35, 0x36, 0x2d, 0x63, 0x62, 
                   0x63, 0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f, 0x75, 
                   0x72, 0x2c, 0x72, 0x69, 0x6a, 0x6e, 0x64, 0x61, 
                   0x65, 0x6c, 0x2d, 0x63, 0x62, 0x63, 0x40, 0x6c, 
                   0x79, 0x73, 0x61, 0x74, 0x6f, 0x72, 0x2e, 0x6c, 
                   0x69, 0x75, 0x2e, 0x73, 0x65, 0x00, 0x00, 0x00, 
                   0x9d, 0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 
                   0x63, 0x74, 0x72, 0x2c, 0x61, 0x65, 0x73, 0x31, 
                   0x39, 0x32, 0x2d, 0x63, 0x74, 0x72, 0x2c, 0x61, 
                   0x65, 0x73, 0x32, 0x35, 0x36, 0x2d, 0x63, 0x74, 
                   0x72, 0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f, 0x75, 
                   0x72, 0x32, 0x35, 0x36, 0x2c, 0x61, 0x72, 0x63, 
                   0x66, 0x6f, 0x75, 0x72, 0x31, 0x32, 0x38, 0x2c, 
                   0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63, 
                   0x62, 0x63, 0x2c, 0x33, 0x64, 0x65, 0x73, 0x2d, 
                   0x63, 0x62, 0x63, 0x2c, 0x62, 0x6c, 0x6f, 0x77, 
                   0x66, 0x69, 0x73, 0x68, 0x2d, 0x63, 0x62, 0x63, 
                   0x2c, 0x63, 0x61, 0x73, 0x74, 0x31, 0x32, 0x38, 
                   0x2d, 0x63, 0x62, 0x63, 0x2c, 0x61, 0x65, 0x73, 
                   0x31, 0x39, 0x32, 0x2d, 0x63, 0x62, 0x63, 0x2c, 
                   0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2d, 0x63, 
                   0x62, 0x63, 0x2c, 0x61, 0x72, 0x63, 0x66, 0x6f, 
                   0x75, 0x72, 0x2c, 0x72, 0x69, 0x6a, 0x6e, 0x64, 
                   0x61, 0x65, 0x6c, 0x2d, 0x63, 0x62, 0x63, 0x40, 
                   0x6c, 0x79, 0x73, 0x61, 0x74, 0x6f, 0x72, 0x2e, 
                   0x6c, 0x69, 0x75, 0x2e, 0x73, 0x65, 0x00, 0x00, 
                   0x00, 0xa7, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x6d, 
                   0x64, 0x35, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 
                   0x73, 0x68, 0x61, 0x31, 0x2c, 0x75, 0x6d, 0x61, 
                   0x63, 0x2d, 0x36, 0x34, 0x40, 0x6f, 0x70, 0x65, 
                   0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 
                   0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 
                   0x61, 0x32, 0x2d, 0x32, 0x35, 0x36, 0x2c, 0x68, 
                   0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x32, 
                   0x2d, 0x32, 0x35, 0x36, 0x2d, 0x39, 0x36, 0x2c, 
                   0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 
                   0x32, 0x2d, 0x35, 0x31, 0x32, 0x2c, 0x68, 0x6d, 
                   0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 
                   0x35, 0x31, 0x32, 0x2d, 0x39, 0x36, 0x2c, 0x68, 
                   0x6d, 0x61, 0x63, 0x2d, 0x72, 0x69, 0x70, 0x65, 
                   0x6d, 0x64, 0x31, 0x36, 0x30, 0x2c, 0x68, 0x6d, 
                   0x61, 0x63, 0x2d, 0x72, 0x69, 0x70, 0x65, 0x6d, 
                   0x64, 0x31, 0x36, 0x30, 0x40, 0x6f, 0x70, 0x65, 
                   0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 
                   0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 
                   0x61, 0x31, 0x2d, 0x39, 0x36, 0x2c, 0x68, 0x6d, 
                   0x61, 0x63, 0x2d, 0x6d, 0x64, 0x35, 0x2d, 0x39, 
                   0x36, 0x00, 0x00, 0x00, 0xa7, 0x68, 0x6d, 0x61, 
                   0x63, 0x2d, 0x6d, 0x64, 0x35, 0x2c, 0x68, 0x6d, 
                   0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x2c, 
                   0x75, 0x6d, 0x61, 0x63, 0x2d, 0x36, 0x34, 0x40, 
                   0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 
                   0x63, 0x6f, 0x6d, 0x2c, 0x68, 0x6d, 0x61, 0x63, 
                   0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x32, 0x35, 
                   0x36, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 
                   0x68, 0x61, 0x32, 0x2d, 0x32, 0x35, 0x36, 0x2d, 
                   0x39, 0x36, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 
                   0x73, 0x68, 0x61, 0x32, 0x2d, 0x35, 0x31, 0x32, 
                   0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 
                   0x61, 0x32, 0x2d, 0x35, 0x31, 0x32, 0x2d, 0x39, 
                   0x36, 0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x72, 
                   0x69, 0x70, 0x65, 0x6d, 0x64, 0x31, 0x36, 0x30, 
                   0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x72, 0x69, 
                   0x70, 0x65, 0x6d, 0x64, 0x31, 0x36, 0x30, 0x40, 
                   0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 
                   0x63, 0x6f, 0x6d, 0x2c, 0x68, 0x6d, 0x61, 0x63, 
                   0x2d, 0x73, 0x68, 0x61, 0x31, 0x2d, 0x39, 0x36, 
                   0x2c, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x6d, 0x64, 
                   0x35, 0x2d, 0x39, 0x36, 0x00, 0x00, 0x00, 0x15, 
                   0x6e, 0x6f, 0x6e, 0x65, 0x2c, 0x7a, 0x6c, 0x69, 
                   0x62, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 
                   0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 
                   0x15, 0x6e, 0x6f, 0x6e, 0x65, 0x2c, 0x7a, 0x6c, 
                   0x69, 0x62, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 
                   0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    
                   0x00, 0x00, 0x02, 0x7c, 0x09, 0x1f, 0x00, 0x00, 
                   0x01, 0x15, 0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 
                   0x68, 0x2d, 0x72, 0x73, 0x61, 0x00, 0x00, 0x00, 
                   0x01, 0x23, 0x00, 0x00, 0x01, 0x01, 0x00, 0xb4, 
                   0xfa, 0x1d, 0xbe, 0x5f, 0x12, 0xd7, 0x45, 0xf3, 
                   0xa8, 0x95, 0x63, 0xcd, 0x7f, 0x30, 0x86, 0x13, 
                   0x96, 0x15, 0xa1, 0x7b, 0x0f, 0x93, 0xf2, 0xa5, 
                   0xd1, 0x8d, 0x2a, 0x9c, 0x2a, 0xd0, 0x15, 0xc2, 
                   0xf4, 0xad, 0x12, 0x71, 0x17, 0xb4, 0x57, 0x4e, 
                   0xb2, 0xf2, 0x64, 0xe3, 0x23, 0xdc, 0xcd, 0x9d, 
                   0x87, 0xf1, 0x49, 0x00, 0xa9, 0x85, 0xc8, 0xec, 
                   0xcf, 0x43, 0x63, 0x79, 0xd8, 0x4c, 0x60, 0xf6, 
                   0x5e, 0x7c, 0xc0, 0x9c, 0x6e, 0x8a, 0x78, 0x2d, 
                   0x8a, 0x2e, 0x89, 0x26, 0x70, 0xb1, 0xc1, 0xaf, 
                   0x39, 0xe4, 0xf6, 0xb3, 0x4a, 0x06, 0x5a, 0x04, 
                   0xb4, 0x26, 0xaf, 0xba, 0xf2, 0xac, 0xa3, 0x45, 
                   0x5e, 0xae, 0xb4, 0x74, 0xc2, 0xff, 0x39, 0x31, 
                   0x07, 0xd0, 0x40, 0x5f, 0xc8, 0xf5, 0x5f, 0x06, 
                   0x03, 0x29, 0xcd, 0xa5, 0x46, 0x54, 0x46, 0x52, 
                   0x47, 0x47, 0x8b, 0x8f, 0x7e, 0xfd, 0xc2, 0xfb, 
                   0x2c, 0x47, 0x59, 0xb8, 0x5b, 0x05, 0x2f, 0xcb, 
                   0xf6, 0x03, 0x02, 0x42, 0x08, 0x75, 0xf7, 0x94, 
                   0x34, 0xbc, 0x14, 0x30, 0xca, 0x20, 0x3b, 0x82, 
                   0xd6, 0x44, 0xce, 0xd2, 0x1d, 0x9a, 0x4c, 0x19, 
                   0x3a, 0x66, 0xfd, 0x8c, 0x12, 0xf6, 0x79, 0x80, 
                   0x78, 0x55, 0x1f, 0x93, 0x34, 0xe3, 0xaa, 0x2b, 
                   0x2f, 0x8f, 0x31, 0x96, 0x99, 0x6f, 0xaa, 0xaa, 
                   0x8a, 0xd3, 0x23, 0xb8, 0xfd, 0xb4, 0xfd, 0x6f, 
                   0x8c, 0xa0, 0xfb, 0xf2, 0xd0, 0xbe, 0x80, 0xe8, 
                   0xb2, 0x0b, 0xf5, 0x68, 0x37, 0xd9, 0x3b, 0xaf, 
                   0x9f, 0x19, 0xcc, 0xaa, 0xb9, 0xfe, 0x10, 0x39, 
                   0xf1, 0x33, 0x64, 0x6a, 0x29, 0x58, 0xaf, 0x34, 
                   0x3f, 0xa1, 0x36, 0x67, 0xc9, 0x62, 0x15, 0x28, 
                   0xd7, 0x69, 0xba, 0xb7, 0xba, 0xf7, 0xe6, 0xc5, 
                   0x13, 0xff, 0x7a, 0x61, 0xbc, 0x1b, 0xfc, 0x3c, 
                   0xc3, 0x9c, 0x02, 0xa9, 0x5f, 0x0d, 0x17, 0x00, 
                   0x00, 0x00, 0x41, 0x04, 0xc5, 0x41, 0x40, 0x68, 
                   0x2c, 0x5d, 0x91, 0xb0, 0xed, 0x9c, 0xe2, 0xc9, 
                   0x1e, 0xfa, 0xc8, 0x40, 0x78, 0xef, 0x29, 0xa9, 
                   0xda, 0x61, 0x1b, 0x41, 0x38, 0xf6, 0xed, 0x09, 
                   0xd8, 0x5f, 0x01, 0x84, 0x39, 0x33, 0x5e, 0xf4, 
                   0x97, 0xc7, 0xec, 0x4e, 0xd1, 0x7b, 0xb9, 0x3c, 
                   0x84, 0x93, 0x64, 0x66, 0x5a, 0x1a, 0x8e, 0x97, 
                   0x20, 0x9c, 0x2a, 0x3d, 0x0e, 0x80, 0xd2, 0xed, 
                   0x96, 0x97, 0x3f, 0xdb, 0x00, 0x00, 0x01, 0x0f, 
                   0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2d, 
                   0x72, 0x73, 0x61, 0x00, 0x00, 0x01, 0x00, 0x18, 
                   0x58, 0x7d, 0xe0, 0x22, 0x28, 0x52, 0xcd, 0x72, 
                   0x33, 0x7c, 0xf4, 0x03, 0x1e, 0x53, 0xba, 0xf9, 
                   0x7f, 0xbe, 0xae, 0xca, 0xd7, 0xb2, 0xd2, 0xb0, 
                   0xa6, 0x64, 0x0e, 0x8b, 0x5a, 0x8e, 0xc1, 0x59, 
                   0x04, 0x81, 0xcd, 0x82, 0xde, 0x92, 0xee, 0x8f, 
                   0xe5, 0x6f, 0x54, 0xad, 0xe0, 0x0f, 0xa0, 0x51, 
                   0xe8, 0xf2, 0x56, 0x4f, 0x1e, 0xab, 0xe1, 0xc3, 
                   0xf2, 0x0c, 0xd9, 0x7e, 0x18, 0x4b, 0x66, 0xea, 
                   0xa3, 0xb2, 0x8a, 0xe3, 0x02, 0x84, 0x8c, 0x2c, 
                   0xf1, 0x53, 0x75, 0xfb, 0xd4, 0xe4, 0x77, 0x85, 
                   0x25, 0xbe, 0x96, 0xcb, 0x66, 0x79, 0xf2, 0xfa, 
                   0xfb, 0x15, 0x63, 0x9e, 0x44, 0xbb, 0xad, 0x58, 
                   0x54, 0x00, 0x02, 0x98, 0xd0, 0xb4, 0xc3, 0x92, 
                   0x8b, 0xa0, 0x51, 0x3b, 0xf4, 0x42, 0xa0, 0x8e, 
                   0x8e, 0xc0, 0xbb, 0xe4, 0xab, 0xfd, 0x7e, 0x41, 
                   0x9c, 0x25, 0xa3, 0x72, 0x67, 0x1c, 0x46, 0x2d, 
                   0x51, 0x22, 0xdf, 0x45, 0x3d, 0xa9, 0x8b, 0xdf, 
                   0x92, 0x51, 0xa7, 0x7e, 0xb1, 0x10, 0x08, 0xa5, 
                   0xd3, 0x68, 0xd5, 0x79, 0x20, 0x54, 0x48, 0x12, 
                   0x87, 0x26, 0xe7, 0x81, 0x8b, 0xc5, 0x6e, 0x80, 
                   0xee, 0x25, 0x37, 0x0d, 0xaf, 0x14, 0x01, 0x63, 
                   0x92, 0x77, 0x12, 0x0e, 0x0e, 0xef, 0xd9, 0x47, 
                   0x4f, 0x8a, 0xa9, 0x60, 0xaf, 0x34, 0x37, 0x37, 
                   0xe8, 0xff, 0x0f, 0xef, 0xb9, 0x7b, 0xc0, 0x9c, 
                   0x9b, 0xd6, 0x9e, 0x0e, 0xd8, 0x19, 0x52, 0x53, 
                   0x4c, 0x2f, 0x36, 0x83, 0xfb, 0xe6, 0x86, 0xe5, 
                   0x8c, 0xe2, 0xd5, 0x18, 0x54, 0x6a, 0x83, 0x81, 
                   0xf7, 0x40, 0xd8, 0x2f, 0xff, 0xd6, 0x94, 0x59, 
                   0xef, 0xb9, 0x09, 0x19, 0x48, 0x29, 0x3c, 0x7e, 
                   0x45, 0xc8, 0x8d, 0x69, 0xb6, 0x7c, 0x03, 0xc6, 
                   0xa4, 0xba, 0x72, 0xb9, 0xb6, 0x39, 0x77, 0xbe, 
                   0xeb, 0x1c, 0x42, 0x13, 0xc1, 0x84, 0x73, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x0c, 0x0a, 0x15, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    
                   0x5c, 0xa9, 0x34, 0x58, 0xbc, 0x68, 0x59, 0x66, 
                   0xbc, 0x03, 0x78, 0x3a, 0x62, 0xb8, 0x2f, 0x79, 
                   0xa9, 0x5f, 0x21, 0xd7, 0x5a, 0x52, 0x27, 0x04, 
                   0xd1, 0x02, 0x46, 0x26, 0xad, 0x78, 0x71, 0xe5, 
                   0x38, 0xc2, 0xd6, 0xdc, 0x79, 0xa9, 0x11, 0xc6, 
                   0x4b, 0xd3, 0xfc, 0x48, 0x30, 0x9d, 0xc0, 0x8a,

                   0x4a, 0x97, 0x0d, 0x3a, 0xe1, 0x26, 0x3a, 0x00, 
                   0xd0, 0xbc, 0xf3, 0xbd, 0xc7, 0xa2, 0x21, 0x01, 
                   0x70, 0x50, 0x1f, 0x80, 0xc0, 0xf4, 0x1f, 0xf1, 
                   0xeb, 0x73, 0x43, 0x09, 0xc2, 0xe6, 0xb3, 0xc0, 
                   0xeb, 0x3b, 0x35, 0x67, 0x10, 0x0c, 0x3f, 0x8f, 
                   0x21, 0xd9, 0xa3, 0x59, 0x85, 0x94, 0x7c, 0x1f, 
                   0xb2, 0xb2, 0x73, 0x25, 0x81, 0x43, 0xeb, 0x86, 
                   0x7f, 0xab, 0xb8, 0x96, 0xb9, 0x63, 0xd9, 0x0a])
    
    def handle(self):
        """
        This handler sends a binary banner
        """
        if args.verbose > 0:
            log.debug("ThreadedActiveTCPRequestHandler: incoming connection. Sending binary banner (OpenSSH)")
        self.request.send(str(ThreadedActiveTCPRequestHandler.banner))
        
        if args.verbose > 0:
            log.debug("ThreadedActiveTCPRequestHandler: banner sent. I will just sleep here for % seconds." % DEFAULT_SERVER_WAIT)
        time.sleep(DEFAULT_SERVER_WAIT)
        if args.verbose > 0:
            log.debug("ThreadedActiveTCPRequestHandler: closing connection")



class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    
    db = []
    
    def __init__(self, server_address, RequestHandlerClass):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        
    def get_request(self):
        ts = str(datetime.now())
        evt = "(CONNECT)"
        ThreadedTCPServer.db.append((ts, evt))
        return SocketServer.TCPServer.get_request(self)
    
    def close_request(self, request):
        SocketServer.TCPServer.close_request(self, request)
        ts = str(datetime.now())
        evt = "(DISCONNECT)"
        ThreadedTCPServer.db.append((ts, evt))

import threading

class NetStatThread(threading.Thread):

    db = []

    def __init__(self):
        super(NetStatThread, self).__init__()
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()
    
    def run(self):
        while(not self.stopped()):
            self._stop.wait(0.5)
            NetStatThread.db.append(utils.pynetstat.netstat())
            pass  

class DirectoryAction(argparse.Action):
    def __call__(self,parser, namespace, values, option_string=None):
        folder = values
        if not os.path.isdir(folder):
            raise argparse.ArgumentTypeError("DirectoryAction:{0}, not a directory".format(folder))
        if os.access(folder, os.R_OK):
            setattr(namespace,self.dest,folder)
        else:
            raise argparse.ArgumentTypeError("DirectoryAction:{0}, cannot read".format(folder))

def bytes_in_dict(d):
    return sum([len(k)+len(v) for k,v in d.iteritems()])

def bytes_in_str(s):
    if s is None:
        return 0
    return len(s)

def _do_request(server_req_data):
    url     = server_req_data.url
    query   = server_req_data.query
    method  = server_req_data.method
    headers = server_req_data.headers
    body    = server_req_data.body
    
    if query is not None and len(query) > 0:
        url = "%s?%s" % (url, query)
    
    http = httplib2.Http(disable_ssl_certificate_validation=True, timeout=args.timeout)
    http.follow_redirects = False
    
    response_data = None
    error = None
    
    try:
        response_data = http.request(url, method, headers=headers, body=body)
        response_data = (response_data[0], response_data[1].decode("utf8", errors="replace").encode('utf8', errors="replace"))
    except Exception as e:
        if args.verbose > 1:
            log.error("_do_request, an error occurred when reading the response: %s" % e)
        error = e.message
    
    if args.verbose > 1:
        log.info("Response: %s" % str(response_data))
    
    return response_data, error

def _do_scan(server_req_data):
    t0 = time.time()
    server_resp_data = None
    error = None

    server_resp_data, error = _do_request(server_req_data)

    t1 = time.time()
    return server_resp_data, error, t0, t1 

def md5_hash(data):
    code = hashlib.md5(str(data)).hexdigest()
    return code

def layered_gzip(data, l=1):
    i = 0
    while i < l:
        compr = _do_gzip(data)
        data = compr
        i += 1
    out = bytearray()
    out += compr
    return out

def _do_gzip(data):
    str_obj = StringIO.StringIO()
    with gzip.GzipFile(fileobj=str_obj, mode="wb") as f:
        f.write(data)
    out = str_obj.getvalue()
    str_obj.close()
    return out

def layered_gunzip(compr, l=1):
    i = 0
    while i < l:
        data = _do_gunzip(compr)
        compr = data
        i += 1
    out = bytearray()
    out += data
    return out

def _do_gunzip(compr):
    str_obj = StringIO.StringIO(compr)
    out = ""
    with gzip.GzipFile(fileobj=str_obj, mode="rb") as f:
        out = f.read()
    str_obj.close()
    return out

def read_file(file):
    data = bytearray()
    f = open(file, "rb")
    try:
        data += f.read()
    except Exception as e:
        raise e
    finally:
        f.close()
    return data
    
def start_monitor():
    global _MONITOR_IS_RUNNING
    _MONITOR_IS_RUNNING = True
    start_http_monitor()
    
    if args.scheme_test and args.tS_scheme == "ftp":
        start_ftp_monitor()
    
    if args.scheme_test and args.tS_scheme != "ftp":
        start_log_tcp_server()
    
    if args.jsbypmaxconn_test:
        start_passive_tcp_server()
        start_netstat_monitor()
        
    if args.sidechannel_test:
        if args.verbose > 1:
            log.info("Side channel analysis configuration: {0} http, {2} CLOSED, {1} DROP, {3}, Pasv srv, and {4} Actv srv".format(args.tSC_open_http, args.tSC_closed_drop, args.tSC_closed_rst, args.tSC_open_bin_passive, args.tSC_open_bin_active))
        add_iptables_rule()
        start_passive_tcp_server()        
        start_active_tcp_server()

        

def start_http_monitor():
    ip = args.bind
    default_port = MONITOR_DEFAULT_PORT
    
    additional_ports = set()
    
    if args.port_test:
        additional_ports.add(args.tP_port) 
    
    if args.sidechannel_test and args.tSC_open_http != default_port:
        additional_ports.add(args.tSC_open_http)
    
    if args.verbose < 1:
        cherrypy.log.screen = None 
    
    def cleanup_default_processors():
        del cherrypy.serving.request.body.processors['application/x-www-form-urlencoded']
        del cherrypy.serving.request.body.processors['multipart/form-data']
        del cherrypy.serving.request.body.processors['multipart']
    cherrypy.tools.cleanup_default_processors = cherrypy.Tool('on_start_resource', cleanup_default_processors)
  
       
    services = [(DetectionService(), "/detect/", {"/":
                                                  {'tools.trailing_slash.on': True,
                                                   'tools.cleanup_default_processors.on': True}})]
    if args.verbose > 0:
        log.info("Using DetectionService")
    
    if args.red_test_only or args.red_test:
        services.append((OpenRedirectorService(), '/red/', {"/":
                                                  {'tools.trailing_slash.on': True,
                                                   'tools.cleanup_default_processors.on': True}}))
        if args.verbose > 0:
            log.info("Using OpenRedirectorService")
    
    if args.jsimage_test or args.jsajax_test or args.jsdur_test or args.jscross_test or args.jsbypmaxconn_test or args.jsworker_test:
        services.append((JSTestsService(), '/js/', {"/":
                                                  {'tools.trailing_slash.on': True,
                                                   'tools.cleanup_default_processors.on': True}}))
        if args.verbose > 0:
            log.info("Using JSTestsService")
    
    if args.sidechannel_test:
        services.append((SideChannelService(), '/sc/', {"/":
                                                  {'tools.trailing_slash.on': True,
                                                   'tools.cleanup_default_processors.on': True}}))
        if args.verbose > 0:
            log.info("Using SideChannelTestsService")

    if args.fetchcompr_test:
        services.append((HtmlBombService(), '/bomb/', {"/":
                                                  {'tools.trailing_slash.on': True,
                                                   'tools.cleanup_default_processors.on': True}}))
        if args.verbose > 0:
            log.info("Using HtmlBombService")
    
    for s in services:
        cherrypy.tree.mount(s[0], s[1], config=s[2])

    cherrypy.server.unsubscribe()
    
    default_server = cherrypy._cpserver.Server()
    default_server._socket_host = ip
    default_server.socket_port = default_port
    default_server.thread_pool = 5
    default_server.nodelay = True
    default_server.subscribe()

    for port in additional_ports:
        server = cherrypy._cpserver.Server()
        server._socket_host = ip
        server.socket_port = port
        server.thread_pool = 5
        server.subscribe()

  
    cherrypy.engine.start()
    if args.verbose > 0:
        log.info("HTTP Monitor is serving on %s ports %s" % (ip, ",".join([str(p) for p in sorted(["(%s)" % default_port] + list(additional_ports))])))

def start_ftp_monitor():
    ip = args.bind
    port = args.tS_port
    
    if args.verbose > 0:
        log.debug("Creating temporary directory for the FTP Anonymous user")
    homedir = tempfile.mkdtemp(prefix="tmp-ftpdmon-")
    
    global ftpserver
    ftpserver = FTPDMonitorThread(ip, port, homedir)
    ftpserver.start()
    
    if args.verbose > 0:
        log.info("FTP Monitor is serving on %s port %s" % (ip, port))

def start_log_tcp_server():
    ip = args.bind
    port = args.tS_port
    global tcp_log_server
    tcp_log_server = ThreadedTCPServer((ip, port), ThreadedTCPRequestLogHandler)

    server_thread = threading.Thread(target=tcp_log_server.serve_forever)

    server_thread.daemon = True
    server_thread.start()
    
    if args.verbose > 0:
        log.info("LogTCPServer is serving on %s port %s" % (ip, port))

def start_passive_tcp_server():
    ip = args.bind
    port = args.tSC_open_bin_passive
    global sc_passive_tcp_server
    sc_passive_tcp_server = ThreadedTCPServer((ip, port), ThreadedPassiveTCPRequestHandler)

    server_thread = threading.Thread(target=sc_passive_tcp_server.serve_forever)

    server_thread.daemon = True
    server_thread.start()
    
    if args.verbose > 0:
        log.info("PassiveTCPServer is serving on %s port %s" % (ip, port))

def start_active_tcp_server():
    ip = args.bind
    port = args.tSC_open_bin_active
    global sc_active_tcp_server
    sc_active_tcp_server = ThreadedTCPServer((ip, port), ThreadedActiveTCPRequestHandler)

    server_thread = threading.Thread(target=sc_active_tcp_server.serve_forever)

    server_thread.daemon = True
    server_thread.start()
    
    if args.verbose > 0:
        log.info("ActiveTCPServer is serving on %s port %s" % (ip, port))

def start_netstat_monitor():
    global netstat_monitor
    netstat_monitor = NetStatThread()
    
    netstat_monitor.daemon = True
    netstat_monitor.start()
    
    if args.verbose > 0:
        log.info("NetStat monitor is running")
        

def add_iptables_rule():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    
    global rule
    rule = iptc.Rule()
    rule.protocol = "tcp"
    rule.dst = args.bind
    
    match = rule.create_match("tcp")
    match.dport = str(args.tSC_closed_drop)
    
    target = rule.create_target("DROP")
    
    chain.insert_rule(rule)
    
    if args.verbose > 0:
        log.info("Adding iptables rule: DROP incoming SYN to {0}, TCP port {1}".format(args.bind, args.tSC_closed_drop))


def stop_monitor():
    
    if not _MONITOR_IS_RUNNING:
        log.info("Monitor(s) not running. Won't stop.")
        return
    
    stop_http_monitor()
    
    if args.scheme_test and args.tS_scheme == "ftp":
        if ftpserver is not None:
            stop_ftp_monitor()
        
    if args.scheme_test and args.tS_scheme != "ftp":
        if tcp_log_server is not None:
            stop_log_tcp_server()

    if args.jsbypmaxconn_test:
        stop_passive_tcp_server()
        stop_netstat_monitor()

    if args.sidechannel_test:
        stop_active_tcp_server()
        stop_passive_tcp_server()
        del_iptables_rule()

def stop_http_monitor():
    if args.verbose > 0:
        log.info("HTTP Monitor being terminated...")
    cherrypy.engine.exit()
    if args.verbose > 0:
        log.info("HTTP Monitor terminated")
    
def stop_ftp_monitor():
    if args.verbose > 0:
        log.info("FTP Monitor being terminated...")
    
    ftpserver.stop()    
    if os.path.isdir(ftpserver.homedir):
        shutil.rmtree(ftpserver.homedir)
    
    if args.verbose > 0:
        log.info("FTP Monitor terminated")

def stop_log_tcp_server():
    if args.verbose > 0:
        log.info("LogTCPServer being terminated...")

    tcp_log_server.shutdown()
    tcp_log_server.server_close()
    
    if args.verbose > 0:
        log.info("LogTCPServer terminated")

def stop_passive_tcp_server():
    if args.verbose > 0:
        log.info("Passive TCPServer being terminated...")

    sc_passive_tcp_server.shutdown()
    sc_passive_tcp_server.server_close()
    
    if args.verbose > 0:
        log.info("Passive TCPServer terminated")

def stop_active_tcp_server():
    if args.verbose > 0:
        log.info("Active TCPServer being terminated...")

    sc_active_tcp_server.shutdown()
    sc_active_tcp_server.server_close()
    
    if args.verbose > 0:
        log.info("Active TCPServer terminated")

def stop_netstat_monitor():
    if args.verbose > 0:
        log.info("NetStat monitor is being terminated...")
    netstat_monitor.stop()
    
    if args.verbose > 0:
        log.info("NetStat monitor terminated")


def del_iptables_rule():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    #if chain.get_target(rule) is not None:
    #    chain.delete_rule(rule)
    
    if args.verbose > 0:
        log.info("Removing iptables rule: DROP incoming SYN to {0}, TCP port {1}".format(args.bind, args.tSC_closed_drop))

    

def fqdn_test(args, monitor_fqdn, json_req, use_red=False):   
    """
    FQDN Test
    """
    ts = str(datetime.now())
    test_type = [FQDN_TEST]
    req_id = md5_hash("FQDN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://%s/detect/?req_id=%s" % (monitor_fqdn, req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
        
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))

          
    resp_data, error = _do_request(server_req_data)

    
    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test


def ip_test(args, monitor_fqdn, monitor_ip, json_req, use_red=False):

    """
    IP Test
    """
    ts = str(datetime.now())
    test_type = [IP_TEST]
    req_id = md5_hash("IP|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://%s/detect/?req_id=%s" % (monitor_ip, req_id)
    
    """
    RED_TEST_ONLY: url is used as target parameter for the open redirector
    """
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)

    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test


def port_test(args, monitor_fqdn, json_req, use_red=False):
    """
    Non-standard port test
    """
    ts = str(datetime.now())
    test_type = [PORT_TEST]
    req_id = md5_hash("PORT|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://%s:%s/detect/?req_id=%s" % (monitor_fqdn, args.tP_port, req_id)
    
    """
    RED_TEST_ONLY: url is used as target parameter for the open redirector
    """
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test


def scheme_test(args,  monitor_fqdn, json_req, use_red=False):
    """
    Non-standard scheme test
    """
    ts = str(datetime.now())
    test_type = [SCHEME_TEST]
    req_id = md5_hash("SCHEME|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "%s://%s/" % (args.tS_scheme, monitor_fqdn)
    if args.tS_scheme == "ftp":
        url += "%s/" % req_id
    elif args.tS_scheme == "gopher":
        url += "1%s" % req_id
    elif args.tS_scheme == "dict":
        url += "d:%s" % req_id
    else:
        url += "X%s" % req_id
    
    """
    RED_TEST_ONLY: url is used as target parameter for the open redirector
    """
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test

def method_test(args, monitor_fqdn, json_req):    
    """
    POST Test
    """
    ts = str(datetime.now())
    test_type = [POST_TEST]
    req_id = md5_hash("FQDN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    
    """ Overwrite method """
    server_req_data.method = "POST"
    
    """ Check if request has a body """
    if server_req_data.bodyp is None or len(server_req_data.bodyp) == 0:
        server_req_data.bodyp = { "par_req_id": req_id }
    
    url = "http://%s/detect/?req_id=%s" % (monitor_fqdn, req_id)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test

def compr_test(args, monitor_fqdn, json_req):    
    """
    Compressed request body test
    """
    ts = str(datetime.now())
    test_type = [COMPR_TEST]
    req_id = md5_hash("COMPR|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    
    """ Overwrite method """
    server_req_data.method = "POST"
    
    """ Check if request has a body """
    if server_req_data.bodyp is None or len(server_req_data.bodyp) == 0:
        server_req_data.bodyp = { "par_req_id": req_id }
    
    url = "http://%s/detect/?req_id=%s" % (monitor_fqdn, req_id)
        
    set_monitor_url(server_req_data, url)
    
    body =  server_req_data.body    
    if args.compr_test_from_file is not None:
        server_req_data.body = bytearray()
        server_req_data.body += args.compr_test_from_file.read()
        server_req_data.headers["Content-Encoding"] = "gzip"
    else:
        """ Ignore input body? """
        if body is None or len(body) == 0:
            log.warning("HTTP request body is empty. Forcing --tCompr-ignore-body behavior")
            body =  "testtest-%s-testtest" % req_id    
        if args.compr_test_override_body:
            body =  "testtest-%s-testtest" % req_id
        
        """ Compression of the body """
        if args.compr_layers in range(1, 4):
            server_req_data.body = layered_gzip(body, l=args.compr_layers) # read_file("data/guenther_preloaded/testtest.gz")
        else:
            log.error(" Unsupported number %s of compression layers. Using 1." % args.compr_layers)
            server_req_data.body = layered_gzip(body, l=1) #read_file("data/guenther_preloaded/testtest.gz")
        
        server_req_data.headers["Content-Encoding"] = str("gzip, " * args.compr_layers)[0:-2]
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    t0 = time.time()
    resp_data, error = _do_request(server_req_data)
    t1 = time.time()

    time.sleep(args.delay)
    
    server_req_data.body = binascii.hexlify(server_req_data.body)
    
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error,
            "d_t"          : t1 - t0,
            }
    
    return test

def jsajax_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JSAjax Test
    """
    ts = str(datetime.now())
    test_type = [JSAJAX_TEST]
    req_id = md5_hash("JSAJAX|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/xmlhttpreqtest?mon=http%3a%2f%2f{mon}%2fjs&req_id={req_id}".format(mon=monitor_fqdn, req_id=req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test

def jsimage_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JSImage Test
    """
    ts = str(datetime.now())
    test_type = [JSIMAGE_TEST]
    req_id = md5_hash("JSIMAGE|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/imagetest?mon=http%3a%2f%2f{mon}%2fjs&req_id={req_id}".format(mon=monitor_fqdn, req_id=req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error,
            }
    
    return test

def jsdur_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JSDur Test
    """
    ts = str(datetime.now())
    test_type = [JSDUR_TEST]
    req_id = md5_hash("JSDUR|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/durtest?mon=http%3a%2f%2f{mon}%2fjs&req_id={req_id}&dur={dur}".format(mon=monitor_fqdn, req_id=req_id, dur=args.jsdur_test-1)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error": error
            }
    
    return test

def jscross_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JS Cross domain test
    """
    ts = str(datetime.now())
    test_type = [JSCROSS_TEST]
    req_id = md5_hash("JSCROSS|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/crossdomaintest?mon=http%3a%2f%2f{mon}%2fjs&req_id={req_id}".format(mon=monitor_fqdn, req_id=req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error": error
            }
    
    return test

def jsbypmaxconn_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JS Cross domain test
    """
    ts = str(datetime.now())
    test_type = [JSBYPMAXCONN_TEST]
    req_id = md5_hash("JSBYPMAXCONN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/bypmaxconn?max={maxr}&mon=ftp%3a%2f%2f{mon}%3a83%2f&req_id={req_id}".format(mon=monitor_fqdn, req_id=req_id,maxr=args.jsbypmaxconn_test)

    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error": error
            }
    
    return test

def jsworker_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    JS Cross domain test
    """
    ts = str(datetime.now())
    test_type = [JSWORKER_TEST]
    req_id = md5_hash("JSBYPMAXCONN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://{mon}/js/webworker?mon=http%3a%2f%2f{mon}%2fjs&req_id={req_id}".format(mon=monitor_fqdn, req_id=req_id)

    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))
    
    resp_data, error = _do_request(server_req_data)

    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error": error
            }
    
    return test


def prepare_url_request(target_host, target_port, http=None, additional_qs=None, use_red=False):
    url_target = "http://{host}:{port}/".format(host=target_host, port=target_port)
    
    if http is not None:
        url_target = "{0}sc/{1}".format(url_target, http) 
    
    if additional_qs is not None:
        url_target = "{base}?{qs}".format(base=url_target, qs=urlencode(additional_qs))
    
    req_id = md5_hash("SCAN|%s" % datetime.now())
    url_request = "{url_target}?{qs}".format(url_target=url_target, 
                                                      qs=urlencode({"req_id": req_id}))
    
    return url_request


def scan(monitor_fqdn, json_req, use_red, target_port, i, http=None, target=None):
    if target is None:
        target = monitor_fqdn
        if args.tSC_target is not None:
            target = args.tSC_target
    
    url_request = prepare_url_request(target, target_port, http=http, use_red=use_red)   
    

    if use_red:
        req_id = md5_hash("SCAN|%s" % datetime.now())
        qs = urlencode({"target":url_request, "req_id":req_id})
        url_request = "http://%s/red/?%s" % (monitor_fqdn, qs)
    
    
    server_req_data = create_request_from_json(json_req)
    set_monitor_url(server_req_data, url_request)
    
    if args.verbose > 1:
        log.info("{0} {1} {2}".format(target_port, i, url_request))
    server_resp_data, error, t0, t1 = _do_scan(server_req_data)
    d_t = t1 - t0
    len_body = -1
    resp_code = -1
    if server_resp_data is not None:
        len_body = len(server_resp_data[1])
        resp_code = server_resp_data[0].status
    res = url_request, target_port, d_t, t0, t1, resp_code, len_body, server_resp_data, error
    return res

def sidechannel_tests(args, monitor_fqdn, json_req, use_red=False):    
    """
    Side Channel Tests
    """
    ts = str(datetime.now())
    test_type = [SC_TEST]
    if use_red:
        test_type.append(REDIR_TEST)
    
    """
    Test loop
    """
    test_results = []
    non_http_ports = [args.tSC_closed_rst, args.tSC_closed_drop, args.tSC_open_bin_passive, args.tSC_open_bin_active]

    if args.verbose > 0:
        log.info("Executing side channel analysis on {target}:{ports}, {tSC_n_scan} scan per port\n".format(target=monitor_fqdn,
                                                                                                ports=non_http_ports+[args.tSC_open_http],
                                                                                                tSC_n_scan=args.tSC_n_scan)) 
     
    """
    HTTP port tests: Existing (small) resource
    """
    batch = itertools.product([args.tSC_open_http], range(args.tSC_n_scan))
    
    if args.verbose > 0:
        log.info("Scan: HTTP+resource+small")
    
    for job in batch:
        target_port, i = job
        
        res  = ("b4", scan(monitor_fqdn, json_req, use_red, target_port, i, http="ok"))
        test_results.append(res)
        
        time.sleep(args.delay)

    """
    HTTP port tests: Existing (big) resource
    """
    batch = itertools.product([args.tSC_open_http], range(args.tSC_n_scan))
    
    if args.verbose > 0:
        log.info("Scan: HTTP+resource+big")
    
    for job in batch:
        target_port, i = job
        
        res  = ("b3", scan(monitor_fqdn, json_req, use_red, target_port, i, http="okbig"))
        test_results.append(res)
        
        time.sleep(args.delay)


    """
    HTTP port tests: Non existing resource
    """
    batch = itertools.product([args.tSC_open_http], range(args.tSC_n_scan))
        
    if args.verbose > 0:
        log.info("Scan: HTTP+non exist. resource")
        
    for job in batch:
        target_port, i = job

        
        res  = ("b5", scan(monitor_fqdn, json_req, use_red, target_port, i, http="nok"))
        test_results.append(res)
        
        time.sleep(args.delay)

    """
    Non HTTP port tests
    """  
    batch = itertools.product(non_http_ports, range(args.tSC_n_scan))
    
    if args.verbose > 0:
        log.info("Scan: non HTTP ports")
                                                           
    for job in batch:
        target_port, i = job
        behaviors = {
                     args.tSC_closed_rst      : "b1",
                     args.tSC_closed_drop     : "b2",
                     args.tSC_open_bin_active : "b6",
                     args.tSC_open_bin_passive: "b7",
                     }
        id = behaviors[target_port]
        res = (id, scan(monitor_fqdn, json_req, use_red, target_port, i))
        test_results.append(res)
        
        time.sleep(args.delay)

    """
    UNREACHABLE HOST test
    """
    
    batch = itertools.product([args.tSC_open_http], range(args.tSC_n_scan))
        
    if args.verbose > 0:
        log.info("Scan: unreachable host test")
        
    for job in batch:
        target_port, i = job

        
        res  = ("b8", scan(monitor_fqdn, json_req, use_red, target_port, i, target=args.tSC_unreachable_host))
        test_results.append(res)
        
        time.sleep(args.delay)


    
    test = {
            "test_type"    : test_type, 
            "analysis_data": test_results
            }
    return test

def hostdisc_test(args, monitor_fqdn, json_req, use_red=False):    
    """
    Host Discovery test
    """
    ts = str(datetime.now())
    test_type = [HD_TEST]
    test_results = []
    
    batch = itertools.product([args.tHD_port], range(args.tSC_n_scan))
     
    if args.verbose > 0:
        log.info("Test: host discovery test")
        
    for job in batch:
        target_port, i = job

        
        res  = ("hostdisc", scan(args.hostdisc_test, json_req, use_red, target_port, i))
        test_results.append(res)
        
        time.sleep(args.delay)

    test = {
            "test_type"    : test_type, 
            "analysis_data": test_results
            }
    return test

def fetch_test(args, monitor_fqdn, json_req, use_red=False):       
    """
    This test checks if the SSR can be used by a client 
    to fetch the content of a resource
    """
    ts = str(datetime.now())
    test_type = [FETCH_TEST]
    req_id = md5_hash("FQDN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    url = "http://%s/detect/?req_id=%s" % (monitor_fqdn, req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
        
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))

          
    resp_data, error = _do_request(server_req_data)

    
    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test

def fetchcompr_test(args, monitor_fqdn, json_req, use_red=False):       
    """
    This test checks if the SSR can be used by a client 
    to fetch the content of a resource
    """
    ts = str(datetime.now())
    test_type = [FETCHCOMPR_TEST]
    req_id = md5_hash("FQDN|%s" % datetime.now())
    server_req_data = create_request_from_json(json_req)
    
    url = "http://%s/bomb/gzipbomb?s=%s&req_id=%s" % (monitor_fqdn, args.fetchcompr_test, req_id)
    
    if use_red:
        test_type.append(REDIR_TEST)
        qs = urlencode({"target":url, "req_id":req_id})
        url = "http://%s/red/?%s" % (monitor_fqdn, qs)
        
    set_monitor_url(server_req_data, url)
    
    if args.verbose > 0:
        log.info("Executing %s" % "+".join([t for t in test_type]))

          
    resp_data, error = _do_request(server_req_data)

    
    time.sleep(args.delay)
   
    test = {
            "timestamp"    : ts, 
            "test_type"    : test_type, 
            "req_id"       : req_id, 
            "inj_url"      : url, 
            "request_data" : server_req_data.to_dict(),
            "response_data": resp_data,
            "error"        : error
            }
    
    return test

def store_to_file(filename, obj):
    abs_path = os.path.join(args.output_folder, filename)

    with open(abs_path, "w") as f:
        json.dump(obj, f, indent=True)

def store_all_json(tests):
    store_to_file("1_tests.json", tests)
    store_to_file("2_openredirector.json", OpenRedirectorService.db)
    store_to_file("3_detection.json", DetectionService.db)
    store_to_file("4_ftpd.json", FTPSchemeDetectionHandler.db)
    store_to_file("5_tcpd.json", ThreadedTCPRequestLogHandler.db+ThreadedTCPServer.db)
    store_to_file("6_httpbombs.json", HtmlBombService.db)
    store_to_file("7_jstests.json", JSTestsService.db)     
    store_to_file("8_netstat.json", NetStatThread.db)
       

def print_all(tests):
    print "==========================="
    print "1 - Tests:"
    print "==========================="
    for r in tests:
        print json.dumps(r, indent=True)

    print "==========================="
    print "2 - HTTP Redirections:"
    print "==========================="
    for entry in OpenRedirectorService.db:
        print json.dumps(entry, indent=True)

    print "==========================="
    print "3 - HTTP Detection:"
    print "==========================="
    for entry in DetectionService.db:
        print json.dumps(entry, indent=True)

    print "==========================="
    print "4 - FTP Detection:"
    print "==========================="
    for entry in FTPSchemeDetectionHandler.db:
        print json.dumps(entry, indent=True)

    print "==========================="
    print "5 - TCP conn. detection:"
    print "==========================="
    for entry in ThreadedTCPRequestLogHandler.db+ThreadedTCPServer.db:
        print json.dumps(entry, indent=True)

    print "==========================="
    print "6 - HTTP Bombs:"
    print "==========================="
    for entry in HtmlBombService.db:
        print json.dumps(entry, indent=True)
    
    print "==========================="
    print "7 - JS tests:"
    print "==========================="
    for entry in JSTestsService.db:
        print json.dumps(entry, indent=True)

    print "==========================="
    print "8 - NetStat:"
    print "==========================="
    for entry in NetStatThread.db:
        print json.dumps(entry, indent=True)

def are_intersect(s1, e1, s2, e2):
    return (s1 <= e2) and (s2 <= e1)

def are_distinguishable(b_i, b_j):
    """
    Check if time intervals are sufficient
    """
    
    s1, e1 = b_i[1:3]
    s2, e2 = b_j[1:3] 
    
    if not are_intersect(s1, e1, s2, e2):
        #print "Distinguishable by dt"
        #print "---"
        return True

    """
    Ok, time was not sufficient. Check with response code
    """

    codes1 = set()
    codes2 = set()
    if hasattr(b_i[3], '__iter__'):
        codes1 = set(b_i[3])
    else:
        codes1.add(b_i[3])
    
    if hasattr(b_j[3], '__iter__'):
        codes2 = set(b_j[3])
    else:
        codes2.add(b_j[3])
    
    if codes1.isdisjoint(codes2):
        #print "Distinguishable by codes"
        #print "---"
        return True
    
    """
    Ok, neither that. Check with content length
    """
    clen1 = set()
    clen2 = set()
    if hasattr(b_i[4], '__iter__'):
        clen1 = set(b_i[4])
    else:
        clen1.add(b_i[4])
    
    if hasattr(b_j[4], '__iter__'):
        clen2 = set(b_j[4])
    else:
        clen2.add(b_j[4])
    
    if clen1.isdisjoint(clen2):
        #print "Distinguishable by clen"
        #print "---"
        return True

    return False

def undistinguishability_matrix(data):
    M = {}
    for b_i, b_j in itertools.product(data.keys(), data.keys()):
        if not are_distinguishable(data[b_i], data[b_j]):
            M.setdefault(b_i, []).append(b_j)
    return M


def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by Giancarlo Pellegrino on %s.
  Copyright 2014. All rights deserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

Usage:
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        
        parser.add_argument("infile", 
                            #dest="infile", 
                            metavar='file',
                            action="store", 
                            nargs='?', # this makes infile optional
                            help="file name of the HTTP request data in Guenther/JSON format [default: stdin]", 
                            type=FileType('r'), 
                            default=sys.stdin)
        
        basic_tests = parser.add_argument_group("Basic tests")
        
        basic_tests.add_argument("-tD",
                            dest="fqdn_test",   
                            action="store_true", 
                            help="Basic test. It tests if the application accepts URL with FQDN, e.g., http://localhost/")

        basic_tests.add_argument("-tI",
                            dest="ip_test",   
                            action="store_true", 
                            help="Basic test. It tests if the application accepts URL with an IP address, e.g., http://127.0.0.1/")
        
        basic_tests.add_argument("-tP",
                            dest="port_test",
                            action="store_true", 
                            help="Basic test. It tests if the application accepts an URL with (i) http scheme, (ii) FQDN , and (iii) a non-standard HTTP port. For the default port, see --tP-port")
        
        
        basic_tests.add_argument("-tS",
                            dest="scheme_test",   
                            action="store_true", 
                            help="Basic test. It tests if the application accepts an URL with a non-HTTP scheme, i.e., %s://localhost/" % SCHEME_TEST_DEFAULT)
        
        basic_tests.add_argument("-tPOST",
                            dest="method_test",   
                            action="store_true", 
                            help="Basic test. It tests if the application accepts POST requests. This option forces the use of POST.")
        
        basic_tests.add_argument("-tComprReq",
                            dest="compr_test",   
                            action="store_true", 
                            help="Basic test. It tests if the application accepts compressed HTTP request body. This option uses compression via content-encoding and forces the use of the POST method. -tD has no effect on this test.")

        basic_tests.add_argument("-tSC",
                            dest="sidechannel_test",   
                            action="store_true", 
                            help="Basic tests. It performs a number of tests to identify distinguishable behaviors to be used for host discovery, port discovery, and/or application fingerprinting.")

        basic_tests.add_argument("-tHD",
                            dest="hostdisc_test",   
                            metavar='host',
                            action="store", 
                            help="Basic tests. It tests if a given host is reachable. This test returns an output similar to -tSC. The output of this test needs to be interpreted with the -tSC output.",
                            type=str)

        basic_tests.add_argument("-tFR",
                            dest="fetch_test",
                            action="store_true", 
                            help="Basic tests. It tests if SSR can be used by a client to fetch a resource.")

        basic_tests.add_argument("-tFComprReq",
                            dest="fetchcompr_test",
                            metavar='int',
                            action="store", 
                            help="Basic tests. It tests if SSR can be used by a client to fetch a compressed resource of a given size (size = 2 ** INT).",
                            type=int)

        basic_tests.add_argument("-tJSAjax",
                            dest="jsajax_test",   
                            action="store_true", 
                            help="Basic tests. It tests if the HTTP client supports the XMLHTTPRequest API.")

        basic_tests.add_argument("-tJSImage",
                            dest="jsimage_test",   
                            action="store_true", 
                            help="Basic tests. It tests if the HTTP client supports the Image() API.")
        
        basic_tests.add_argument("-tJSDur",
                            dest="jsdur_test",
                            metavar='int',
                            action="store", 
                            help="Basic tests. It measures how long JavaScript is executed. Specify time in seconds. This override the value of -w.",
                            type=int)
        
        basic_tests.add_argument("-tJSCrossDomain",
                            dest="jscross_test",
                            action="store_true", 
                            help="Basic tests. It tests whether the HTTP client allows for cross-domain XMLHTTPRequests.")

        basic_tests.add_argument("-tJSBypMaxConn",
                            dest="jsbypmaxconn_test",
                            metavar="int",
                            action="store", 
                            help="Basic tests. It tests whether it is possible to bypass the maximum connection limit.",
                            type=int)        
        
        basic_tests.add_argument("-tJSWebWorker",
                            dest="jsworker_test",
                            action="store_true", 
                            help="Basic tests. It tests whether the HTTP client supports Web Worker.")
        
        """
        PORT test options
        """
        
        tP_group = parser.add_argument_group("Non-standard HTTP port test options")
        

        tP_group.add_argument("--tP-port", 
                            metavar='n',
                            dest="tP_port",   
                            action="store", 
                            help="custom TCP port for -tP. [default= %(default)s]", 
                            default = PORT_TEST_DEFAULT,
                            type=int)
        
        """
        SCHEME test options
        """
        
        tS_group = parser.add_argument_group("URL scheme test options")
        
        tS_group.add_argument("--tS-scheme", 
                            dest="tS_scheme",
                            metavar='scheme', 
                            action="store", 
                            help="custom URL scheme. Supported schemes " + ", ".join(SCHEME_TO_PORT.keys()) + " [default: %(default)s]", 
                            default=SCHEME_TEST_DEFAULT,
                            type=str)

        tS_group.add_argument("--tS-port", 
                            dest="tS_port",
                            metavar='n',  
                            action="store", 
                            help="custom TCP port for -tS. [default=default port of --tS-scheme]",
                            type=int)

        """
        HTTP Redirection options
        """

        red_group = parser.add_argument_group("HTTP Redirection options")
        
        tR_mut_excl_group = red_group.add_mutually_exclusive_group()

        tR_mut_excl_group.add_argument("-tR",
                            dest="red_test",   
                            action="store_true", 
                            help="It uses HTTP redirection to test the application against input validation bypass. This option executes the selected basic tests twice: with and without HTTP 302 redirection.")
        
        tR_mut_excl_group.add_argument("-tRx",
                            dest="red_test_only",   
                            action="store_true", 
                            help="It changes the behavior of basic tests by using HTTP 302 redirections.")

        """
        HTTP Compression options
        """
        
        tCompr_group = parser.add_argument_group("HTTP Compression payload options")

        tCompr_group.add_argument("--tComprReq-ignore-body",
                            dest="compr_test_override_body",   
                            action="store_true", 
                            help="Ignore the 'bodyp' field of the request")

        tCompr_group.add_argument("--tComprReq-layers", 
                            dest="compr_layers",
                            metavar='n',   
                            action="store", 
                            help="the number of compression layers. This changes the Content-Encoding value, e.g., with 3 the content encoding header will be 'Content-Encoding: gzip, gzip, gzip' [default: %(default)s]", 
                            default=1, 
                            type=int)
        
        tCompr_group.add_argument("--tComprReq-body-from-file",
                            dest="compr_test_from_file",   
                            metavar='file',
                            action="store",
                            help="file name of a gzipped file", 
                            type=FileType('r'))

        """
        Side Channel Tests Options
        """
        
        tSC_group = parser.add_argument_group("Side Channel Analysis options")

        tSC_group.add_argument("--tSC-n-scan", 
                            metavar='n',
                            dest="tSC_n_scan",   
                            action="store", 
                            help="number of scans per port. [default= %(default)s]", 
                            default = SC_N_SCANS,
                            type=int)


        tSC_group.add_argument("--tSC-closed-rst", 
                            metavar='n',
                            dest="tSC_closed_rst",   
                            action="store", 
                            help="custom TCP port that is closed and returns RST upon SYN. [default= %(default)s]", 
                            default = SC_CLOSED_RST_DEFAULT,
                            type=int)
        
        tSC_group.add_argument("--tSC-closed-drop", 
                            metavar='n',
                            dest="tSC_closed_drop",   
                            action="store", 
                            help="custom TCP port that is closed and drops messages (i.e., port filtered). [default= %(default)s]", 
                            default = SC_CLOSED_DROP_DEFAULT,
                            type=int)
        
        tSC_group.add_argument("--tSC-open-http", 
                            metavar='n',
                            dest="tSC_open_http",   
                            action="store", 
                            help="custom TCP port for the HTTP server. [default= %(default)s]", 
                            default = MONITOR_DEFAULT_PORT,
                            type=int)

        tSC_group.add_argument("--tSC-open-bin-passive", 
                            metavar='n',
                            dest="tSC_open_bin_passive",   
                            action="store", 
                            help="custom TCP port for a passive TCP server. [default= %(default)s]", 
                            default = SC_OPEN_BIN_PASSIVE_PORT,
                            type=int)

        tSC_group.add_argument("--tSC-open-bin-active", 
                            metavar='n',
                            dest="tSC_open_bin_active",   
                            action="store", 
                            help="custom TCP port for a passive TCP server. [default= %(default)s]", 
                            default = SC_OPEN_BIN_ACTIVE_PORT,
                            type=int)

        tSC_group.add_argument("--tSC-unreachable-host", 
                            metavar='host',
                            dest="tSC_unreachable_host",   
                            action="store", 
                            help="IP of a host that is unreachable. [default= %(default)s]", 
                            default = SC_UNREACH_HOST,
                            type=str)
        
        tSC_group.add_argument("--tSC-target", 
                            metavar='host',
                            dest="tSC_target",   
                            action="store", 
                            help="IP of a host that is unreachable.", 
                            default = None,
                            type=str)
        """
        Monitor Options
        """
        hd_group = parser.add_argument_group("Host discovery options")
        
        hd_group.add_argument("-tHD-port",
                            dest="tHD_port",   
                            metavar='host',
                            action="store", 
                            help="Port to be used for the host discovery.",
                            default=80,
                            type=int)

        """
        Monitor Options
        """
        monitor_group = parser.add_argument_group("Monitor options")
        
        monitor_group.add_argument("-b", "--bind",  
                            dest="bind", 
                            metavar='host',
                            action="store", 
                            help="address to bind the monitor.", 
                            type=str,
                            required=True)

        monitor_group.add_argument("-P", "--public",  
                            metavar='host',
                            dest="public", 
                            action="store", 
                            help="FQDN of the monitor.", 
                            type=str,
                            required=True)

        monitor_group.add_argument("--monitor-only",  
                            dest="monitor_only", 
                            action="store_true", 
                            help="run the monitor only. To stop the monitor, press CTRL+C")
        
        """
        Other
        """
               
        parser.add_argument("-w", "--wait", 
                            dest="wait", 
                            metavar='n',
                            action="store", 
                            help="time in seconds before shutting down the monitors [default: %(default)s]", 
                            default=5, 
                            type=float)

        parser.add_argument("-d", "--delay", 
                            dest="delay",
                            metavar='n', 
                            action="store", 
                            help="interval in seconds between two consecutive requests [default: %(default)s]", 
                            default=2, 
                            type=float)

        parser.add_argument("--timeout", 
                            dest="timeout", 
                            metavar='n',  
                            action="store", 
                            help="TCP timeout [default: %(default)s]", 
                            default=30, 
                            type=int)
               
        parser.add_argument("-v", "--verbose",         
                            dest="verbose", 
                            action="count", 
                            help="set verbosity level [default: %(default)s]")

        parser.add_argument('-V', '--version',  
                            action='version', 
                            version=program_version_message)

        """
        Arguments for the output
        """
        output_group = parser.add_argument_group("Output options")
        
        output_group.add_argument("-E", "--export-output",
                            metavar='folder',
                            dest="output_folder",   
                            action=DirectoryAction,
                            help="output folders where to store JSON output data",
                            )

        output_group.add_argument("--csv-tables",  
                            dest="csv_tables", 
                            action="store_true", 
                            help="prints the tests and scan output in a CSV table format.")
        
        # Process arguments
        global args
        args = parser.parse_args()

        if args.verbose > 0:
            log.info("Verbose mode on, level %s" % args.verbose)
            
            if args.verbose < len(utils.log.LEVELS):
                log.setLevel(utils.log.LEVELS[args.verbose])

                
            if args.verbose > 1:
                httplib2.debuglevel = args.verbose
        
        if args.monitor_only:
            log.info("Monitor-only mode: >> NO TEST WILL BE EXECUTED <<")
                           
        # adjust default value for scheme port
        if args.scheme_test and not args.tS_port:
            args.tS_port = SCHEME_TO_PORT[args.tS_scheme]
        
        # check that ports do not conflict
        if args.port_test and args.scheme_test:
            if args.tP_port == args.tS_port:
                log.error("PORT and SCHEME test must use different port.")
                raise Exception("PORT and SCHEME test must use different port.")
        
        
        """
        STARTING THE MONITOR
        """ 
        start_monitor()

        tests = []  
        if not args.monitor_only:
            """
            READING HTTP REQUEST FORMAT
            """
            
            json_req = args.infile.read()
                        
            if not args.csv_tables:
                sys.stdout.write("Testing %s ...\n" % json.loads(json_req)["urlp"])
            
            monitor_fqdn = args.public
            if args.verbose > 2:
                log.debug("Monitor public FQDN is %s" % monitor_fqdn)
            
            monitor_ip = socket.gethostbyname_ex(args.public)[2][0]
            if args.verbose > 2:
                log.debug("Monitor public IP is %s" % monitor_ip)

            """
            Basic tests that do not use/need redirection
            """

            if args.method_test:
                if json.loads(json_req)["method"] == "POST":
                    log.error("Original request is already a POST request. Skipping test.")
                else:
                    test = method_test(args, monitor_fqdn, json_req)
                    tests.append(test)
    
            if args.compr_test:
                test = compr_test(args, monitor_fqdn, json_req)
                tests.append(test)

            """
            Basic tests with -tRx
            """
            
            if args.fqdn_test:
                test = fqdn_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
    
            if args.ip_test:
                test = ip_test(args, monitor_fqdn, monitor_ip, json_req, use_red=args.red_test_only)
                tests.append(test)
                
            if args.port_test:
                test = port_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
                
            if args.scheme_test:
                test = scheme_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
                
            if args.jsimage_test:
                test = jsimage_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)

            if args.jsajax_test:
                test = jsajax_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)

            if args.jsdur_test:
                test = jsdur_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)

            if args.jscross_test:
                test = jscross_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)

            if args.jsbypmaxconn_test:
                test = jsbypmaxconn_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)                
            
            if args.jsworker_test:
                test = jsworker_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
                
                
            if args.sidechannel_test:
                test = sidechannel_tests(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
            
            if args.hostdisc_test:
                test = hostdisc_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
                        
            if args.fetch_test:
                test = fetch_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
            
            if args.fetchcompr_test:
                test = fetchcompr_test(args, monitor_fqdn, json_req, use_red=args.red_test_only)
                tests.append(test)
            
            """
            Basic test with -tD
            """
            if args.red_test:
                if args.fqdn_test:
                    test = fqdn_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
        
                if args.ip_test:
                    test = ip_test(args, monitor_fqdn, monitor_ip, json_req, use_red=args.red_test)
                    tests.append(test)
                    
                if args.port_test:
                    test = port_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
                    
                if args.scheme_test:
                    test = scheme_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
                
                if args.jsimage_test:
                    test = jsimage_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)

                if args.jsajax_test:
                    test = jsajax_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
                
                if args.jsdur_test:
                    test = jsdur_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)

                if args.jscross_test:
                    test = jscross_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)

                if args.jsbypmaxconn_test:
                    test = jsbypmaxconn_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)

                if args.sidechannel_test:
                    test = sidechannel_tests(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
            
                if args.hostdisc_test:
                    test = hostdisc_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
                
                if args.fetch_test:
                    test = fetch_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
                    
                if args.fetchcompr_test:
                    test = fetchcompr_test(args, monitor_fqdn, json_req, use_red=args.red_test)
                    tests.append(test)
            
            if not args.csv_tables:
                sys.stdout.write("Selected tests: %s\n" % ", ".join(["+".join(r["test_type"]) for r in tests]))
            
            if args.verbose > 0:
                log.debug("Monitor will be shutdown in %s secs..." % args.wait)
            time.sleep(args.wait)
        
        else:
            """
            Run only monitors.
            """
            log.info("Press CTRL+C to quit")
            try:
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                log.info("Exitting monitor only mode")

        stop_monitor()
        
        if args.verbose > 3:
            print_all(tests)      
        
        if args.output_folder:
            store_all_json(tests)  
        
        if not args.monitor_only:
            detect_req_ids = map(lambda entry: entry[1], DetectionService.db)
            redir_req_ids = map(lambda entry: entry[1], OpenRedirectorService.db)
            
            def print_dir_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                if req_id in detect_req_ids:
                    outb.append("OK")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
    
            def print_dir_ftp_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ftp_req_ids = filter(lambda entry: req_id in entry[4][0], FTPSchemeDetectionHandler.db)
                if len(ftp_req_ids) > 0:
                    outb.append("OK")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

                
            def print_dir_tcp_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                tcp_req_ids = filter(lambda entry: req_id in entry[2], ThreadedTCPRequestLogHandler.db)
                if len(tcp_req_ids) > 0:
                    outb.append("OK")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
    
            def print_red_http_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                if req_id in redir_req_ids and req_id in detect_req_ids:
                    outb.append("OK")
                elif req_id in redir_req_ids:
                    outb.append("FAIL")
                elif req_id in detect_req_ids:
                    outb.append("ERROR (unexpected: red FAIL, det OK)")
                else:
                    outb.append("RED FAIL")
                    
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
    
            
            def print_red_ftp_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ftp_req_ids = filter(lambda entry: req_id in entry[4][0], FTPSchemeDetectionHandler.db)
                
                if req_id in redir_req_ids and len(ftp_req_ids) > 0:
                    outb.append("OK")
                elif req_id in redir_req_ids:
                    outb.append("FAIL")
                elif len(ftp_req_ids) > 0:
                    outb.append("ERROR (unexpected: red FAIL, det OK)")
                else:
                    outb.append("RED FAIL")
     
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
     
            def print_red_tcp_result(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                tcp_req_ids = filter(lambda entry: req_id in entry[2], ThreadedTCPRequestLogHandler.db)
                if req_id in redir_req_ids and len(tcp_req_ids) > 0:
                    outb.append("OK")
                elif req_id in redir_req_ids:
                    outb.append("FAIL")
                elif len(tcp_req_ids) > 0:
                    outb.append("ERROR (unexpected: red FAIL, det OK)")
                else:
                    outb.append("RED FAIL")
     
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
            
            def print_ssr_is_post(test, test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ssrs = map(lambda el: el[2], filter(lambda el: el[1] == req_id, DetectionService.db))
                
                if len(ssrs) > 0:
                    req = ssrs[0]
                    if req["method"] == "POST":
                        outb.append("OK")
                    else:
                        outb.append("FAIL")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
            
            def print_id_in_respbody(test, test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                if req_id in test["response_data"][1]:
                    outb.append("OK")
                else:
                    outb.append("FAIL")
     
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
     
            def print_id_in_ssrbody(test, test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ssrs = map(lambda el: el[2], filter(lambda el: el[1] == req_id, DetectionService.db))
                    
                if len(ssrs) > 0:
                    req = ssrs[0]
                    if req["body"] is not None and req_id in req["body"]:
                        outb.append("OK")
                    else:
                        outb.append("FAIL")
                else:
                    outb.append("FAIL")
                    
     
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
     
            def print_scan_result(test_descr, tests):
                outb = []
                url = json.loads(json_req)["urlp"]
                             
                for test in tests:
                    id, data = test
                    url_request, target_port, d_t, t0, t1, resp_code, len_body, server_resp_data, error = data                    
                    outb.append([url, test_descr, str(id), str(target_port), str(d_t), str(resp_code), str(len_body), str(error)])
                        
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    for l in outb:
                        csvout.writerow(l)
                else:
                    for l in outb:
                        sys.stdout.write("- ")
                        sys.stdout.write(" ".join(l[1:]))
                        sys.stdout.write("\n")
            
            def tests_to_flat_data(tests):
                outb = []
                # flattening tests, see also +1 below
                tests = [[t[0]]+list(t[1]) for t in tests]
                tests = sorted(tests, key = lambda test: test[0])
               
                for id, data in itertools.groupby(tests, lambda test: test[0]):
                    data = list(data)
                    d_ts = map(lambda test: test[2+1], data)
                    avg_dt, min_dt, max_dt = utils.math.mean_confidence_interval(d_ts)

                    codes    = set(map(lambda test: test[5+1], data))
                    if len(codes) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, codes))
                    codes = ", ".join([str(c) for c in codes])
                    
                    
                    lens_body = set(map(lambda test: test[6+1], data))
                    if len(lens_body) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, lens_body))
                    lens_body = ", ".join([str(c) for c in lens_body])
                    
                    errors   = set(map(lambda test: test[8+1], data))
                    if len(errors) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, errors))
                    errors = ", ".join([str(c) for c in errors])
                    
                    outb.append([str(id), str(avg_dt), str(min_dt), str(max_dt), str(codes), str(lens_body), str(errors)])
                    
                return outb

            def tests_to_struct_data(tests):
                outb = []
                # flattening tests, see also +1 below
                tests = [[t[0]]+list(t[1]) for t in tests]
                tests = sorted(tests, key = lambda test: test[0])
               
                for id, data in itertools.groupby(tests, lambda test: test[0]):
                    data = list(data)
                    d_ts = map(lambda test: test[2+1], data)
                    avg_dt, min_dt, max_dt = utils.math.mean_confidence_interval(d_ts)

                    codes    = set(map(lambda test: test[5+1], data))
                    if len(codes) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, codes))
                    codes = list(codes)
                    
                    
                    lens_body = set(map(lambda test: test[6+1], data))
                    if len(lens_body) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, lens_body))
                    lens_body = list(lens_body)
                    
                    errors   = set(map(lambda test: test[8+1], data))
                    if len(errors) > 1:
                        log.warning("Behavior {0} has >1 distinct response codes: {1}".format(id, errors))
                    errors = list(errors)
                    
                    outb.append([id, avg_dt, min_dt, max_dt, codes, lens_body, errors])
                    
                return outb

            
            def print_aggr_scan_result(test_descr, tests):
                outb = []
                url = json.loads(json_req)["urlp"]
                
                data = tests_to_flat_data(tests)
                for el in data:
                    outb.append([url, test_descr] + el)
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    for l in outb:
                        csvout.writerow(l)
                else:
                    for l in outb:
                        sys.stdout.write("- ")
                        sys.stdout.write(" ".join(l[1:]))
                        sys.stdout.write("\n")
            
            def print_behav_classes(test_descr, tests):
                outb = []
                url = json.loads(json_req)["urlp"]
                
                def to_dict(raw):
                    return {d[0]: d[1:] for d in raw}
                
                data = tests_to_struct_data(tests)
                data = to_dict(data)
                """
                Calculate UNDISTINGUISHABILITY MATRIX
                """
                
                M = undistinguishability_matrix(data)
                
                for k in sorted(M.keys()):
                    outb.append([url, "undist_matrix", k, ",".join(sorted(M[k]))])
                          
                """
                States for Behaviors
                """
                dist_behav= {}
                for k in M.keys():
                    for k_i in M[k]:
                        for b in b_map[k_i]:
                            dist_behav.setdefault(k, (set(), set(), set()))
                            el = dist_behav[k]
                            if b in [SCA_STATUS_P_OPEN, SCA_STATUS_P_CLOSED, SCA_STATUS_P_FILTERED]:
                                el[2].add(labels[b])
                            if b in [SCA_STATUS_R_EXIST, SCA_STATUS_R_NON_EXIST_404, SCA_STATUS_R_NON_EXIST]:
                                el[1].add(labels[b])
                            if b in [SCA_STATUS_H_ONLINE, SCA_STATUS_H_OFFLINE]:
                                el[0].add(labels[b])

                for k in sorted(dist_behav):
                    outb.append([url, "states_for_behaviors", k, ", ".join(list(dist_behav[k][0])), ", ".join(list(dist_behav[k][1])), ", ".join(list(dist_behav[k][2]))])

                """
                Classes of States
                """
                S_classes = {}
            
                els = [[k]+sorted([list(v[0])+list(v[1])+list(v[2])]) for k, v in dist_behav.items()]
                els = sorted(els, key = lambda el: el[1])
                for ls, b in itertools.groupby(els, lambda el: el[1]):
                    S_classes[frozenset([p[0] for p in list(b)])] = ls
                
                for k, v in sorted(S_classes.items(), key=lambda el: sorted(list(el[0]))):
                    outb.append([url, "classes_of_states", "-".join(sorted(list(k))), ", ".join(v)])

                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    for l in outb:
                        csvout.writerow(l)
                else:
                    for l in outb:
                        sys.stdout.write("- ")
                        sys.stdout.write("  ".join(l[1:]))
                        sys.stdout.write("\n")
     
            def print_nr_reqs(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                reqs = filter(lambda el: el == req_id, detect_req_ids)
                outb.append(str(len(reqs)))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            def print_size_sent(test_descr, test, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                req = test["request_data"]
                b_sent = 0               
                b_sent += bytes_in_str(req["url"])
                b_sent += bytes_in_str(req["query"])
                b_sent += bytes_in_str(req["body"])
                b_sent += bytes_in_dict(req["headers"])
                
                outb.append(str(b_sent))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
            
            def print_size_rcvd_ssr(test_descr, test, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ssrs = map(lambda el: el[2], filter(lambda el: el[1] == req_id, DetectionService.db))

                b_rcvd = 0                        
                b_rcvd += sum(map(lambda el: bytes_in_str(el["method"]), ssrs))
                b_rcvd += sum(map(lambda el: bytes_in_str(el["url"]), ssrs))
                b_rcvd += sum(map(lambda el: bytes_in_dict(el["qs"]), ssrs))
                b_rcvd += sum(map(lambda el: bytes_in_str(el["body"]), ssrs))
                b_rcvd += sum(map(lambda el: bytes_in_dict(el["headers"]), ssrs))
                
                outb.append(str(b_rcvd))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
                    
            def print_size_rcvd(test_descr, test, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                resp = test["response_data"]
                
                code = resp[0]["status"]
                del resp[0]["status"] # stuff added by httplib
                headers = resp[0]
                body = resp[1]
                            
                b_rcvd = 0               
                b_rcvd += bytes_in_str(code)
                b_rcvd += bytes_in_str(body)
                b_rcvd += bytes_in_dict(headers)
                
                outb.append(str(b_rcvd))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
                    
            def print_fetch_result(test, test_descr, req_id):                
                outb = [json.loads(json_req)["urlp"], test_descr]
                
                if test["response_data"][1] is not None and test["response_data"][1].endswith("with req_id=%s done." % req_id):
                    outb.append("OK")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            def print_js_req_id_test(test_descr, req_id, test_name):
                jstests_req_ids = map(lambda entry: (entry[1], entry[2]), JSTestsService.db)
                
                outb = [json.loads(json_req)["urlp"], test_descr]
                if (req_id, test_name) in jstests_req_ids:
                    outb.append("OK")
                else:
                    outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            def print_count_js_ping(test_descr, req_id):
                pings = filter(lambda entry: entry[1] == req_id and entry[2] == "Ping", JSTestsService.db)
                
                outb = [json.loads(json_req)["urlp"], test_descr, str(len(pings))]
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")
                    
            def print_count_ssr_ftp(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                ftp_data = filter(lambda entry: req_id in entry[4][0], FTPSchemeDetectionHandler.db)
                ftp_data = sorted(ftp_data, key = lambda entry: (entry[2], entry[3]))
                Kl = list(itertools.groupby(ftp_data, lambda entry: (entry[2], entry[3])))
                outb.append(str(len(Kl)))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            #def print_count_max_par_conn(test_descr, req_id):
            #    outb = [json.loads(json_req)["urlp"], test_descr]
            #    ftp_data = ThreadedTCPServer.db
            #    ftp_data = sorted(ftp_data, key = lambda entry: entry[0])
            #    
            #    est = 0
            #    conn = 0
            #    maxc = 0
            #    for entry in ftp_data:
            #        if "(CONNECT)" in entry[1]:
            #            est = est + 1
            #            maxc = max(est, maxc)
            #        #if "(DISCONNECT)" in entry[1]:
            #        #    est = est - 1
            #    
            #    outb.append(str(maxc))
            #    
            #    if args.csv_tables:
            #        csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
            #        csvout.writerow(outb)
            #    else:
            #        sys.stdout.write("- ")
            #        sys.stdout.write(" ".join(outb[1:]))
            #        sys.stdout.write("\n")

            def print_count_max_par_conn(test_descr, req_id):
                outb = [json.loads(json_req)["urlp"], test_descr]
                data = NetStatThread.db
                maxest = 0
                maxtwait = 0
                for sample in data:
                    s_est = filter(lambda entry: entry[2] == "{0}:{1}".format(monitor_ip, str(83)) and entry[4] == "ESTABLISHED", sample)
                    s_twait = filter(lambda entry: entry[2] == "{0}:{1}".format(monitor_ip, str(83)) and entry[4] == "TIME_WAIT", sample)
                    est = len(s_est)
                    twait = len(s_twait)
                    maxest = max(maxest, est)
                    maxtwait = max(maxtwait, twait)
                        
                outb.append(str(maxest))
                outb.append(str(maxtwait))
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            def print_js_req_id_qs_test(test_descr, req_id, test_name, par):
                jstests_req_ids = map(lambda entry: (entry[1], entry[2], entry[3]["qs"]), JSTestsService.db)
                jstests_req_ids = filter(lambda entry: entry[1] == test_name, jstests_req_ids)
                outb = [json.loads(json_req)["urlp"], test_descr]
                if len(jstests_req_ids) == 0:
                    outb.append("FAIL")
                else:
                    found = False
                    for el in jstests_req_ids:
                        if req_id in el[0] and par in el[2]:
                            outb.append(el[2][par])
                            found = True
                            break
                    if not found:
                        outb.append("FAIL")
                
                if args.csv_tables:
                    csvout = csv.writer(sys.stdout, delimiter=';', quoting=csv.QUOTE_MINIMAL)
                    csvout.writerow(outb)
                else:
                    sys.stdout.write("- ")
                    sys.stdout.write(" ".join(outb[1:]))
                    sys.stdout.write("\n")

            if args.fqdn_test:
                """
                TODO: this test is wrongly called "fetch". This is an input validation test and it does not check if
                the resource is returned to the client. The latter test is done by the fetch resource test.
                
                1) Fetch HTTP
                """
                fqdn_tests = filter(lambda test: FQDN_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(fqdn_tests) > 1:
                    log.warning("Unexpected number of tests for FQDN. The output is not complete. Please check the logs.")
                test = fqdn_tests[0]
    
                req_id = test["req_id"]
                print_dir_result("Fetch HTTP content...", req_id)
                print_nr_reqs("Number of SSRs...", req_id)
                print_size_sent("Bytes sent...", test, req_id)
                print_size_rcvd_ssr("Bytes rcvd...", test, req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    2) Redirection HTTP
                    """
                    fqdn_tests = filter(lambda test: FQDN_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(fqdn_tests) > 1:
                        log.warning("Unexpected number of tests for FQDN+RED. The output is not complete. Please check the logs.")
                    test = fqdn_tests[0]
                    
                    req_id = test["req_id"]
                    print_red_http_result("Redirect to HTTP content...", req_id)                
    
                
            if args.ip_test:
                """
                3) Accept IP address
                """
                ipaddr_tests = filter(lambda test: IP_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(ipaddr_tests) > 1:
                    log.warning("Unexpected number of tests for IPaddr. The output is not complete. Please check the logs.")
                test = ipaddr_tests[0]
    
                req_id = test["req_id"]
                print_dir_result("Accept IP address...", req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    4) Redirection to IP address
                    """
                    ipaddr_tests = filter(lambda test: IP_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(ipaddr_tests) > 1:
                        log.warning("Unexpected number of tests for IPaddr+RED. The output is not complete. Please check the logs.")
                    test = ipaddr_tests[0]
    
                    req_id = test["req_id"]
                    print_red_http_result("Redirect to IP address...", req_id)    
                
            if args.port_test:
                """
                5) Accept port
                """
                port_tests = filter(lambda test: PORT_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(port_tests) > 1:
                    log.warning("Unexpected number of tests for PORT. The output is not complete. Please check the logs.")
                test = port_tests[0]
    
                req_id = test["req_id"]
                print_dir_result("Accept TCP port ({0})...".format(args.tP_port), req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    6) Redirection to TCP port
                    """
                    port_tests = filter(lambda test: PORT_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(port_tests) > 1:
                        log.warning("Unexpected number of tests for PORT+RED. The output is not complete. Please check the logs.")
                    test = port_tests[0]
                    
                    req_id = test["req_id"]
                    print_red_http_result("Redirect to TCP port ({0})...".format(args.tP_port), req_id)  
            
            if args.scheme_test:
                """
                7) Accept scheme
                """
                scheme_tests = filter(lambda test: SCHEME_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(scheme_tests) > 1:
                    log.warning("Unexpected number of tests for SCHEME. The output is not complete. Please check the logs.")
                test = scheme_tests[0]
                
                req_id = test["req_id"]
    
                if args.tS_scheme == "ftp":
                    print_dir_ftp_result("Accept scheme ({0})...".format(args.tS_scheme), req_id)
                else:
                    print_dir_tcp_result("Accept scheme ({0})...".format(args.tS_scheme), req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    8) Redirection to scheme
                    """
                    scheme_tests = filter(lambda test: SCHEME_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(scheme_tests) > 1:
                        log.warning("Unexpected number of tests for SCHEME+RED. The output is not complete. Please check the logs.")
                    test = scheme_tests[0]
                    
                    req_id = test["req_id"]
                    
                    if args.tS_scheme == "ftp":
                        print_red_ftp_result("Redirect to SCHEME port ({0})...".format(args.tS_scheme), req_id)  
                    else:
                        print_red_tcp_result("Redirect to SCHEME port ({0})...".format(args.tS_scheme), req_id)
            
            if args.method_test:
                """
                9) FORCE POST
                """
                if json.loads(json_req)["method"] != "POST":                    
                    post_tests = filter(lambda test: POST_TEST in test["test_type"], tests)
                    if len(post_tests) > 1:
                        log.warning("Unexpected number of tests for POST. The output is not complete. Please check the logs.")
                    test = post_tests[0]
        
                    req_id = test["req_id"]
                    print_dir_result("Force GET to POST...", req_id)
                    print_ssr_is_post(test, "SSR is POST...", req_id)
                    print_id_in_ssrbody(test, "Reuse of POST body in SSRs...", req_id)
                    
                
            if args.compr_test:
                """
                10) Content-Encoding gzip
                """
                compr_tests = filter(lambda test: COMPR_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(compr_tests) > 1:
                    log.warning("Unexpected number of tests for COMPR. The output is not complete. Please check the logs.")
                test = compr_tests[0]
                
                req_id = test["req_id"]
                
                if args.compr_test_from_file is None:
                    print_dir_result("Accepted gzip encoding in requests...", req_id)          
                    print_id_in_ssrbody(test, "Decompress gzip body...", req_id)
                else:
                    print_nr_reqs("Number of SSRs...", req_id)
                    print_size_sent("Bytes sent...", test, req_id)
                    print_size_rcvd_ssr("Bytes rcvd...", test, req_id)

            if args.sidechannel_test:
                """
                11) Side channel analysis
                """
                sc_tests = filter(lambda test: SC_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(sc_tests) > 1:
                    log.warning("Unexpected number of tests for SC_TEST. The output is not complete. Please check the logs.")
                tests = sc_tests[0]["analysis_data"]
                print_scan_result("SCA direct reqs", tests)
                print_aggr_scan_result("SCA direct reqs consolid data", tests)
                print_behav_classes("SCA direct reqs behav classes", tests)
                
                    
                if args.red_test or args.red_test_only:
                    log.debug(sc_tests)
                    sc_tests = filter(lambda test: SC_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(sc_tests) > 1:
                        log.warning("Unexpected number of tests for SC_TEST. The output is not complete. Please check the logs.")
                    tests = sc_tests[0]["analysis_data"]
                    print_scan_result("SCA HTTP redir", tests)
                    print_aggr_scan_result("SCA HTTP redir consolid data", tests)
                    print_behav_classes("SCA direct reqs behav classes", tests)
    
            if args.hostdisc_test:
                """
                12) Host reachability test
                """
                sc_tests = filter(lambda test: HD_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(sc_tests) > 1:
                    log.warning("Unexpected number of tests for HD_TEST. The output is not complete. Please check the logs.")
                tests = sc_tests[0]["analysis_data"]
                print_scan_result("Host discovery test", tests)
                
                if args.red_test or args.red_test_only:
                    sc_tests = filter(lambda test: HD_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(sc_tests) > 1:
                        log.warning("Unexpected number of tests for HD_TEST. The output is not complete. Please check the logs.")
                    tests = sc_tests[0]["analysis_data"]
                    print_scan_result("Host discovery with redirection test", tests)
                    
            if args.fetch_test:
                """
                13) Fetch resource
                """
                fetch_tests = filter(lambda test: FETCH_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(fetch_tests) > 1:
                    log.warning("Unexpected number of tests for FETCH. The output is not complete. Please check the logs.")
                test = fetch_tests[0]
    
                req_id = test["req_id"]
                print_fetch_result(test, "Fetch resource...", req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    14) Redirection HTTP
                    """
                    fqdn_tests = filter(lambda test: FETCH_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(fqdn_tests) > 1:
                        log.warning("Unexpected number of tests for FETCH+RED. The output is not complete. Please check the logs.")
                    test = fqdn_tests[0]
                    
                    req_id = test["req_id"]
                    print_fetch_result(test, "Fetch resource...", req_id)

            if args.fetchcompr_test:
                """
                15) Fetch bomb
                """
                fetch_tests = filter(lambda test: FETCHCOMPR_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(fetch_tests) > 1:
                    log.warning("Unexpected number of tests for FETCHCOMPR. The output is not complete. Please check the logs.")
                test = fetch_tests[0]
    
                req_id = test["req_id"]
                print_size_rcvd("Response size", test, req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    16) Redirection HTTP
                    """
                    fetch_tests = filter(lambda test: FETCHCOMPR_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(fetch_tests) > 1:
                        log.warning("Unexpected number of tests for FETCHCOMPR+RED. The output is not complete. Please check the logs.")
                    test = fetch_tests[0]
                    
                    req_id = test["req_id"]
                    print_size_rcvd("Response size", test, req_id)

            if args.jsimage_test:
                """
                17) JS Image API test
                """
                jsimg_test = filter(lambda test: JSIMAGE_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jsimg_test) > 1:
                    log.warning("Unexpected number of tests for JSIMAGE_TEST. The output is not complete. Please check the logs.")
                test = jsimg_test[0]
    
                req_id = test["req_id"]
                print_js_req_id_test("Support JavaScript Image() API", req_id, "Ping")

                
                if args.red_test or args.red_test_only:
                    """
                    18) JS Image API test w/ redirect
                    """
                    jsimg_test = filter(lambda test: JSIMAGE_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jsimg_test) > 1:
                        log.warning("Unexpected number of tests for JSIMAGE_TEST+RED. The output is not complete. Please check the logs.")
                    test = jsimg_test[0]
                    
                    req_id = test["req_id"]
                    print_js_req_id_test("(redirect) Support JavaScript Image() API", req_id, "Ping")

            if args.jsajax_test:
                """
                19) JS Ajax API test
                """
                jsajax_tests = filter(lambda test: JSAJAX_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jsajax_tests) > 1:
                    log.warning("Unexpected number of tests for JSAJAX_TEST. The output is not complete. Please check the logs.")
                test = jsajax_tests[0]
    
                req_id = test["req_id"]
                print_js_req_id_test("Support JavaScript XMLHTTPRequest API", req_id, "Ping")

                
                if args.red_test or args.red_test_only:
                    """
                    20) JS Ajax API test w/ redirect
                    """
                    jsajax_tests = filter(lambda test: JSAJAX_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jsajax_tests) > 1:
                        log.warning("Unexpected number of tests for JSAJAX_TEST+RED. The output is not complete. Please check the logs.")
                    test = jsajax_tests[0]
                    
                    req_id = test["req_id"]
                    print_js_req_id_test("(redirect) Support JavaScript XMLHTTPRequest API", req_id, "Ping") 

            if args.jsdur_test:
                """
                21) Duration of JS execution
                """
                jsdur_tests = filter(lambda test: JSDUR_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jsdur_tests) > 1:
                    log.warning("Unexpected number of tests for JSDUR_TEST. The output is not complete. Please check the logs.")
                test = jsdur_tests[0]
    
                req_id = test["req_id"]
                print_count_js_ping("Duration of JS execution", req_id)

                
                if args.red_test or args.red_test_only:
                    """
                    22) Duration of JS execution test w/ redirect
                    """
                    jsdur_tests = filter(lambda test: JSDUR_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jsdur_tests) > 1:
                        log.warning("Unexpected number of tests for JSDUR_TEST+RED. The output is not complete. Please check the logs.")
                    test = jsdur_tests[0]
                    
                    req_id = test["req_id"]
                    print_count_js_ping("(redirect) Duration of JS execution", req_id)  

            if args.jscross_test:
                """
                23) Cross Domain test
                """
                jscross_tests = filter(lambda test: JSCROSS_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jscross_tests) > 1:
                    log.warning("Unexpected number of tests for JSCROSS_TEST. The output is not complete. Please check the logs.")
                test = jscross_tests[0]
    
                req_id = test["req_id"]
                print_js_req_id_test("Cross-domain XMLHTTPRequest", req_id, "Ping")
                
                if args.red_test or args.red_test_only:
                    """
                    24) Cross Domain test w/ redirect
                    """
                    jscross_tests = filter(lambda test: JSCROSS_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jscross_tests) > 1:
                        log.warning("Unexpected number of tests for JSCROSS_TEST+RED. The output is not complete. Please check the logs.")
                    test = jscross_tests[0]
                    
                    req_id = test["req_id"]
                    print_js_req_id_test("(redirect) Cross-domain XMLHTTPRequest", req_id, "Ping")
                    
            if args.jsbypmaxconn_test:
                """
                25) By pass max connection
                """
                jscross_tests = filter(lambda test: JSBYPMAXCONN_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jscross_tests) > 1:
                    log.warning("Unexpected number of tests for JSBYPMAXCONN_TEST. The output is not complete. Please check the logs.")
                test = jscross_tests[0]
    
                req_id = test["req_id"]
                print_js_req_id_test("Bypass max connections per host limit", req_id, "Bypass Max. Conn.")
                print_count_max_par_conn("TCP connection status", req_id)
                
                if args.red_test or args.red_test_only:
                    """
                    26) CBy pass max connection w/ redirect
                    """
                    jscross_tests = filter(lambda test: JSBYPMAXCONN_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jscross_tests) > 1:
                        log.warning("Unexpected number of tests for JSBYPMAXCONN_TEST+RED. The output is not complete. Please check the logs.")
                    test = jscross_tests[0]
                    
                    req_id = test["req_id"]
                    print_js_req_id_test("(redirect) Bypass max connections per host limit", req_id, "Bypass Max. Conn.")
                    print_count_max_par_conn("(redirect) TCP connection status", req_id)

            if args.jsworker_test:
                """
                27) WebWorker
                """
                jsworker_tests = filter(lambda test: JSWORKER_TEST in test["test_type"] and REDIR_TEST not in test["test_type"], tests)
                if len(jsworker_tests) > 1:
                    log.warning("Unexpected number of tests for JSWORKER_TEST. The output is not complete. Please check the logs.")
                test = jsworker_tests[0]
    
                req_id = test["req_id"]
                print_js_req_id_qs_test("Support WebWorker API", req_id, "Ping", "result")

                
                if args.red_test or args.red_test_only:
                    """
                    28) WebWorker w/ redirect
                    """
                    jsworker_tests = filter(lambda test: JSWORKER_TEST in test["test_type"] and REDIR_TEST in test["test_type"], tests)
                    if len(jsworker_tests) > 1:
                        log.warning("Unexpected number of tests for 0+RED. The output is not complete. Please check the logs.")
                    test = jsworker_tests[0]
                    
                    req_id = test["req_id"]
                    print_js_req_id_qs_test("(redirect) Support WebWorker API", req_id, "Ping", "result") 

        if args.verbose > 0:
            log.info("is exiting.")
        return 0

    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        log.info("Keyboard interrupt\n")
        stop_monitor()
        return 0
    except Exception, e:
        log.fatal("Exception %s - %s" % (type(e), e))
        stop_monitor()
        
        if DEBUG or TESTRUN:
            raise
        
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help\n")
        return 2



if __name__ == "__main__":
    if DEBUG:
        #sys.argv.append("-h")
        sys.argv.append("-v")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'scanner.guenther_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())

