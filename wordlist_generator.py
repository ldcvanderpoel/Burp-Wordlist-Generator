'''
A Burp extension to extract various data from the sitemap. This data can
later be used in personalized wordlists.

Created by Laurens van der Poel (ldcvanderpoel).
'''

import threading
import os
from uuid import uuid4
from urlparse import urlparse

from burp import IBurpExtender
from burp import IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem
from burp.IParameter import PARAM_BODY,PARAM_JSON,PARAM_URL,PARAM_XML
from burp.IContextMenuInvocation import CONTEXT_TARGET_SITE_MAP_TREE
from java.awt import Frame

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        '''
        Extension initialization.
        A unique directory is created for each seperate project.
        '''
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Wordlist Generator")
        callbacks.registerContextMenuFactory(self)

        # Set up wordlist output directory
        self.wordlistDir = os.path.abspath(os.getcwd()) + \
            '/wordlists/' + self.getProjectTitle() + '/'
        if not os.path.exists(self.wordlistDir):
            os.makedirs(self.wordlistDir)

        print('Wordlist generator initialized.')
        print('Writing to directory: ' + self.wordlistDir)

    def createMenuItems(self, invocation):
        '''
        Creates the context menu entry when right clicking the site map.
        '''
        context = invocation.getInvocationContext()

        if context != CONTEXT_TARGET_SITE_MAP_TREE:
            return

        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Generate wordlist from sitemap",
                                actionPerformed=self.menuAction)
        menuList.add(menuItem)
        return menuList


    def menuAction(self, event):
        '''
        Basic threaded menu action.
        Prevents the UI from freezing.
        '''
        t = threading.Thread(target=self.generateWordlist)
        t.daemon = True
        t.start()
    

    def generateWordlist(self):
        '''
        Loop over the sitemap and add collect data for the wordlists.
        Only in-scope items are considered.
        Current wordlists created:
        - Path
        - Parameter keys
        - Parameter values
        - Parameter key-value pairs (query)
        - Subdomain
        '''

        print('Generating wordlist.')
        self.paths = set()
        self.keys = set()
        self.values = set()
        self.queries = set()
        self.subdomains = set()

        # Loop over sitemap
        for requestResponse in self._callbacks.getSiteMap(None):
            requestInfo = self._helpers.analyzeRequest(requestResponse)

            # Ignore out-of-scope requests
            url = requestInfo.getUrl()
            if not self._callbacks.isInScope(url):
                print('Not in scope, skipped: ' + str(url))
                continue
            
            # Try to gather data
            try:
                self.processPath(requestInfo)
                self.processSubdomain(requestInfo)

                for param in requestInfo.getParameters():
                    self.processParams(param)
            except:
                print('An error occured during processing of: ' + str(url)\
                    + ' (skipped).')
                
        print('Storing wordlists.')
        self.storeWordlist(self.paths, 'paths.txt')
        self.storeWordlist(self.keys, 'keys.txt')
        self.storeWordlist(self.values, 'values.txt')
        self.storeWordlist(self.queries, 'queries.txt')
        self.storeWordlist(self.subdomains, 'subdomains.txt')
        print('Done!')

    def processPath(self, requestInfo):
        '''
        Extract path from URL.
        '''
        url = requestInfo.getUrl()
        path = urlparse(str(url)).path
        self.paths.add(path)
    
    def processSubdomain(self, requestInfo):
        '''
        Get subdomains from URL. E.g.
        acc.v1.website.com => acc.v1
        '''
        url = requestInfo.getUrl()
        subdomain = '.'.join(urlparse(str(url)).netloc.split('.')[:-2])
        self.subdomains.add(subdomain)

    def processParams(self, param):
        '''
        Extract parameter keys, values, and key-value pairs (queries).
        Parameters from cookies, multipart forms, and XML attributes are
        ignored (PARAM_COOKIE, PARAM_MULTIPART_ATTR, and PARAM_XML_ATTR).

        `bytesToString` is necessary (instead of str()), because `param.getName` 
        and `param.getValue()` return bytes.
        '''
        if int(param.getType()) not in [
            PARAM_URL,
            PARAM_BODY,
            PARAM_JSON,
            PARAM_XML
            ]:
            return
        
        key = self._helpers.bytesToString(param.getName())
        value = self._helpers.bytesToString(param.getValue())
        query = key + '=' + value
        self.keys.add(key)
        self.values.add(value)
        self.queries.add(query)

    def storeWordlist(self, list, filename):
        '''
        Store wordlists.
        '''
        with open(self.wordlistDir + filename, 'w') as file:
            for item in list:
                file.write(item+'\n')

    def getProjectTitle(self):
        '''
        Get the current project title.
        There is no direct API call for this. Therefore, we retrieve
        the title from the UI frame object.
        '''
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith('Burp Suite'):
                projectTitle = frame.getTitle().split('-')[1].strip()
                # NOTE: This does not work for project names containing '-'.
                return projectTitle
