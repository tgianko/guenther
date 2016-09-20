'''
Created on Sep 15, 2014

@author: gianko

For thread-safe decorator class, see Francis Avila http://stackoverflow.com/questions/13610654/how-to-make-built-in-containers-sets-dicts-lists-thread-safe 
'''

"""
Usage:
ClassDecoratorLockedSet(...)

"""
from threading import RLock
from collections import deque

class UniqueQueue():
    def __init__(self):
        self.queue = []
        self.set = set()
        self.i = -1

    def add(self, d):
        if not d in self.set:
            self.queue.append(d)
            self.set.add(d)

    def join(self, l):
        l = set(l) # remove internal redudancies
        for d in l:
            self.add(d)

    def pop(self):
        d = self.queue.pop(0)
        self.set.remove(d)
        return d
    
    def __len__(self):
        return len(self.set)

    def __iter__(self):
        return self.queue.__iter__()

class UniqueDeque():
    def __init__(self):
        self.queue = deque()
        self.set = set()
        self.i = -1

    def add(self, d):
        if not d in self.set:
            self.queue.append(d)
            self.set.add(d)

    def join(self, l):
        l = set(l) # remove internal redudancies
        for d in l:
            self.add(d)

    def pop(self):
        d = self.queue.pop()
        self.set.remove(d)
        return d
    
    def __len__(self):
        return len(self.set)

    def __iter__(self):
        return self.queue.__iter__()


def lock_class(methodnames, lockfactory):
    return lambda cls: make_threadsafe(cls, methodnames, lockfactory)

def lock_method(method):
    if getattr(method, '__is_locked', False):
        raise TypeError("Method %r is already locked!" % method)
    def locked_method(self, *arg, **kwarg):
        with self._lock:
            return method(self, *arg, **kwarg)
    locked_method.__name__ = '%s(%s)' % ('lock_method', method.__name__)
    locked_method.__is_locked = True
    return locked_method


def make_threadsafe(cls, methodnames, lockfactory):
    init = cls.__init__
    def newinit(self, *arg, **kwarg):
        init(self, *arg, **kwarg)
        self._lock = lockfactory()
    cls.__init__ = newinit

    for methodname in methodnames:
        oldmethod = getattr(cls, methodname)
        newmethod = lock_method(oldmethod)
        setattr(cls, methodname, newmethod)

    return cls

@lock_class(['add','remove', "__contains__"], RLock)
class LockedSet(set):
    pass
    #@lock_method # if you double-lock a method, a TypeError is raised
    #def frobnify(self):
    #    pass