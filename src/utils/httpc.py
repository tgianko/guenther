'''
Created on Sep 5, 2014

This is a multi-threaded, webkit-based web crawler.

Support for REDIS not properly tested.


@author: gianko

'''

import utils.log as log
from utils.common import LockedSet

from webscraping.webkit import WebPage, NetworkAccessManager

from PyQt4.QtCore import QTimer, QUrl, QThread
from PyQt4.QtGui import QApplication
from PyQt4.QtWebKit import QWebView, QWebElement, QWebSettings
from PyQt4.QtNetwork import QNetworkRequest

import redis

from collections import deque
import urlparse, sys, json


LOGGER = log.getdebuglogger("utils.web")
  
NUM_THREADS = 10 # how many threads to use
MAX_LEVEL = 1   # max depth

_URLs_SET_KEY = "crawler:data"

def normalize_url(base, url):
    return urlparse.urljoin(base, url)

def normalize_form(url, form):
    if "action" in form["attributes"]:
        form["attributes"]["action"] = normalize_url(url, form["attributes"]["action"])
    else:
        LOGGER.debug("No FORM action found: %s" % form["attributes"])
    return form

class Crawler(QWebView):
    c_active = deque()      # track how many threads are still active
    
    data = {}             # store the data
    
    frontier = deque()    # Frontier
    
    visited = LockedSet() # Visited URLs
    

    def __init__(self, name, app, scope, r_server, delay=1, proxy=None, forbidden_extensions=None, allowed_regex='.*?'):
        QWebView.__init__(self)
        self.name = name
        self.app = app
        self.scope = scope
        self.r_server = r_server
        self.delay = delay
        self.current_level = -1
        self.async_res = []
        self._t_pool = dict()
        LOGGER.debug("<%s> Initialized" % name)
        
        manager = NetworkAccessManager(proxy, forbidden_extensions, allowed_regex)
        manager.finished.connect(self._on_finished)
        webpage = WebPage("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36")
        webpage.setNetworkAccessManager(manager)
        #webpage.mainFrame().javaScriptWindowObjectCleared.connect(self._on_jsWinObjCleared)
        
        self.setHtml('<html><head></head><body><h1>Multithreaded Crawler</h1><p>Waiting for orders, sir!</p></body></html>', QUrl('http://localhost'))
        self.setPage(webpage)
        self.loadFinished.connect(self._on_loadFinished)
        
        self.settings().setAttribute(QWebSettings.PluginsEnabled, True)
        self.settings().setAttribute(QWebSettings.JavaEnabled, True)
        self.settings().setAttribute(QWebSettings.AutoLoadImages, True)
        self.settings().setAttribute(QWebSettings.DeveloperExtrasEnabled, True)

        
    def start(self, urls):
        LOGGER.info("<%s> Started" % self.name)
        Crawler.frontier = urls

        self._run()

    def _run(self):
        LOGGER.debug("<%s> Crawling" % self.name) 
        try:
            depth, url = Crawler.frontier.pop()
            LOGGER.info("<%s> Fetched %s, depth %s/%s." % (self.name, url, depth, MAX_LEVEL))
            LOGGER.info("<%s> Frontier size %s" % (self.name, len(Crawler.frontier)))             
            if self._filter(url, depth):
                LOGGER.debug("<%s> Fetching %s" % (self.name, url))
                Crawler.c_active.append(1)
                self.current_level = depth # I need this here when adding URL to the frontier
                self.load(QUrl(url))
                
            else:
                LOGGER.info("<%s> Skipping %s" % (self.name, url))
                self._schedule_task(1000, self._run)
            
        except IndexError:
            # no more urls to process
            if not Crawler.c_active:
                # no more threads downloading
                LOGGER.debug("<%s> No more crawler active. Terminating" % self.name)
                self.close()
            else:
                LOGGER.debug("<%s> No URL in the frontier. Rescheduling" % self.name)
                self._schedule_task(1000, self._run)

    def _out_of_scope(self, url):
        for dom in self.scope:
            if not urlparse.urlparse(url).hostname.endswith(dom):
                return True
        
        return False

    def _filter(self, url, current_depth):

        """
        This function decides whether or not a URL must be fetched.
        
        Criteria (OR):
        1) Maximum depth reached
        2) URL already visited
        3) URL out of the scope
        """
        if current_depth > MAX_LEVEL:
            LOGGER.debug("<%s> MAX_LEVEL reached. Skipping %s" % (self.name, url))
            return False
        
        if url in Crawler.visited:
            LOGGER.debug("<%s> URL visited. Skipping %s" % (self.name, url))
            return False
        
        if url.split("#")[0] in Crawler.visited:
            LOGGER.debug("<%s> URL visited (without fragment). Skipping %s" % (self.name, url))
            return False
        
        if self._out_of_scope(url):
            LOGGER.debug("<%s> URL out of scope. Skipping %s" % (self.name, url))
            return False

        return True

    def _schedule_task(self, timeout, callback):                  
        """
        Schedule the execution of callback after timeout.
        
        This is implemented by keeping a timer object for each function. 
        """
        LOGGER.debug("<%s> Scheduling execution of %s in %s" % (self.name, callback.__name__, timeout))
        for k, t in self._t_pool.iteritems():
            LOGGER.debug("<%s> %s:%s, %s" % (self.name, k.__name__, t, t.isActive()))
        
        def call_and_cleanup():
            callback()
            del self._t_pool[call_and_cleanup]
        
        self._t_pool[call_and_cleanup] = QTimer()
        self._t_pool[call_and_cleanup].setSingleShot(True)
        self._t_pool[call_and_cleanup].timeout.connect(call_and_cleanup)
        self._t_pool[call_and_cleanup].start(timeout)


    def _on_loadFinished(self, result):
        #def callback(result):
        #    self._process_doc(result)
        #    self._schedule_task(1000, self._run) # after processing the data reschedule the crawler execution
        #self._schedule_task(4000, lambda: callback(result))
        
        
        
        self._process_doc(result)
        self._schedule_task(1000, self._run)
        


    def _redis_store(self, name, **kwargv):
        """
        HMSET key href $json_href links $links async_res $async_res
        """
        self.r_server.sadd(_URLs_SET_KEY, name)
        
        for k, v in kwargv.iteritems():
            v_json = json.dumps(v)
            #print name, k, v_json
            self.r_server.hset(name, k, v_json)

    def _process_doc(self, result):
        frame = self.page().mainFrame() 
        url = str(frame.url().toString())
        
        Crawler.visited.add(url)
        #print frame.toHtml()
        """
        Preparing output
        """
        hrefs = self.extract_hrefs()
        hrefs = map(lambda href: normalize_url(url, href), hrefs)
        hrefs = list(set(hrefs))

        forms = self.extract_forms()
        forms = map(lambda form: normalize_form(url, form), forms)

        async_res = self.async_res
        self.async_res = [] # we reset this otherwise for the next URL
        
        LOGGER.info("<%s> OUTPUT %s:\n|hrefs|=%s\n|forms|=%s\n|async_res|=%s" % (self.name, url, len(hrefs), len(forms), len(async_res)))
        """
        Storing output
        """
        #CrawlerBrowser.data.setdefault(url, (hrefs, forms))
        LOGGER.debug("<%s> Storing data" % self.name)
               
        self._redis_store(url, hrefs=hrefs, forms=forms, async_res=async_res)
 
        Crawler.data[url] = (hrefs, forms, async_res)

        """
        Updating frontier
        """        

        d_frontier = filter(lambda e:self.current_level < MAX_LEVEL, hrefs)
        LOGGER.debug("<%s> Enqueuing new %s links." % (self.name, len(d_frontier)))
        
        for href in d_frontier:
            Crawler.frontier.appendleft((self.current_level+1, href))


        #hrefs = set(hrefs)
        #LOGGER.info("<%s> URL %s new %s unique links" % (self.name, url, len(hrefs)))
        

        try:
            Crawler.c_active.popleft()
        except Exception as e:
            LOGGER.error("<%s> %s" % (self.name, e))



    def _on_finished(self, result):
        """
        This method stores the URLs of the resources fetched by the crawler when
        interpreting the HTML code. Here, we will find javascript, json, and AJAX
        call in general. This method will capture also images and CSS files.
        """
        url = unicode(result.url().toString())
        status = result.attribute(QNetworkRequest.HttpStatusCodeAttribute).toInt()
        res = (url, status)
        self.async_res.append(res)

    def _on_jsWinObjCleared(self):
        LOGGER.info("<%s> javaScriptWindowObjectCleared event fired")


    def find(self, pattern):
        """Returns whether element matching css pattern exists
        Note this uses CSS syntax, not Xpath
        """
        # format xpath to webkit style
        #pattern = re.sub('["\']\]', ']', re.sub('=["\']', '=', pattern.replace('[@', '[')))
        if isinstance(pattern, basestring):
            matches = self.page().mainFrame().findAllElements(pattern).toList()
        elif isinstance(pattern, list):
            matches = pattern
        elif isinstance(pattern, QWebElement):
            matches = [pattern]
        else:
            LOGGER.info('Unknown pattern: ' + str(pattern))
            matches = []
        return matches
         
    def extract_hrefs(self):
        qt4elements = self.find("a")
        hrefs = map(lambda e: e.attribute("href"), qt4elements)
        return hrefs
    
    def extract_forms(self):
        out = []
        forms = self.find("form")
        for f in forms:
            f_out = {
                     "attributes": dict([(k, f.attribute(k)) for k in f.attributeNames()]),
                     "inputs": [],
                     "textareas": [],
                     "selects": []
                     }
            out.append(f_out)
            
            inputs = f.findAll("input")
            for i in inputs:#
                i_out = {
                         "attributes": dict([(k, i.attribute(k)) for k in i.attributeNames()])
                         }
                f_out["inputs"].append(i_out)
                
             
            textareas = f.findAll("textarea")   
            for t in textareas:#
                t_out = {
                         "attributes": dict([(k, t.attribute(k)) for k in t.attributeNames()]),
                         "text": t.toPlainText()
                         }
                f_out["textareas"].append(t_out)
        
            selects = f.findAll("select")   
            for s in selects:
                s_out = {
                         "attributes": dict([(k, s.attribute(k)) for k in s.attributeNames()]),
                         "options": []
                         }
                f_out["selects"].append(s_out)
                
                options = s.findAll("option")
                for o in options:
                    o_out = {
                             "attributes": dict([(k, o.attribute(k)) for k in o.attributeNames()]),
                             "text": o.toPlainText()
                             }
                    s_out["options"].append(o_out)
        return out

def runCrawlers(seed_set, scope=[], maxdlev=MAX_LEVEL, thrnum=NUM_THREADS):
    global MAX_LEVEL, NUM_THREADS
    MAX_LEVEL = maxdlev
    NUM_THREADS = thrnum
    
    app = QApplication(sys.argv)
    
    hprioQ = deque(zip([0 for i in range(len(seed_set))], seed_set)) 
    
    LOGGER.info("Connecting to Redis...")
    s_server = redis.StrictRedis("localhost", db="0")
    LOGGER.info("Flushing DB... %s" % s_server.flushdb())
    
    renders = [Crawler("Crawler-%s"% i, app, scope, s_server, proxy="127.0.0.1:8081") for i in range(NUM_THREADS)]
    
    for r in renders:
        LOGGER.info("Starting Crawler %s" % r.name)
        r.start(hprioQ)
    
    LOGGER.info("Crawlers are up and running.")
    
    app.exec_() 
    
    LOGGER.info("Crawlers finished.")
    for url in Crawler.data:
        print url, Crawler.data[url]



if __name__ == '__main__':
    #runCrawlers(["http://localhost/crawler/index.html", "http://localhost/crawler/index2.html"], maxdlev=2)
    #runCrawlers(["http://www.google.com", "http://www.youtube.com", "http://www.yahoo.de", "http://www.gmx.de"], maxdlev=1)
    #runCrawlers(["http://www.yahoo.de"], maxdlev=1)
    
    runCrawlers(["http://validator.w3.org/"], scope=["w3.org"], maxdlev=1, thrnum=5)