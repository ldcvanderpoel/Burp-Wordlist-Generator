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
from javax.swing import JMenuItem, JRadioButton
from burp.IParameter import PARAM_BODY,PARAM_JSON,PARAM_URL,PARAM_XML
from burp.IContextMenuInvocation import CONTEXT_TARGET_SITE_MAP_TREE
from java.awt import Frame

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        '''
        Extension initialization.
        A unique directory is created for each seperate project.
        '''
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
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

        menuList = ArrayList()
        menuItem = JMenuItem("Generate wordlist from entire sitemap",
                                actionPerformed=self.menuActionFull)
        menuList.add(menuItem)

        self.selection = invocation.getSelectedMessages()
        if len(self.selection) > 0:
            menuItem = JMenuItem("Generate wordlist from selection",
                                actionPerformed=self.menuActionSelection)
            menuList.add(menuItem)
        return menuList


    # TODO: Two menu actions is ugly, but I'm not sure how to pass
    # arguments to `actionPerformed` in `JMenuItem`. Perhaps inspiration
    # can be drawn from Autorize:
    # https://github.com/Quitten/Autorize/blob/ce5479755cb152c0b65185b3d484665852d66506/gui/menu.py
    def menuActionFull(self, event):
        '''
        Basic threaded menu action.
        Prevents the UI from freezing.
        '''
        
        sitemap = self._callbacks.getSiteMap(None)
        t = threading.Thread(target=self.generateWordlist, args=(sitemap,))
        t.daemon = True
        t.start()


    def menuActionSelection(self, event):
        '''
        Basic threaded menu action.
        Prevents the UI from freezing.
        '''
        
        selection = self.selection
        t = threading.Thread(target=self.generateWordlist, args=(selection,))
        t.daemon = True
        t.start()

    def generateWordlist(self, requestResponses):
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
        count = 0

        # Loop over sitemap
        total = len(requestResponses)
        for requestResponse in requestResponses:
            count += 1
            requestInfo = self._helpers.analyzeRequest(requestResponse)
            url = requestInfo.getUrl().toString().encode('utf-8')   
            method = requestInfo.getMethod().encode('utf-8')

            # Ignore out-of-scope requests
            if not self._callbacks.isInScope(requestInfo.getUrl()):
                print('[%i/%i]: %s (Not in scope, skipped)' % (count, total, url))
                continue

            print('[%i/%i]: %s %s' % (count, total, method, url))

            # Try to gather data
            try:
                self.processPath(url)
                self.processSubdomain(url)

                for param in requestInfo.getParameters():
                    self.processParams(param)
            except:
                sys.stderr.write('An error occured during processing of "%s"\n'\
                    % url)
                sys.stderr.flush()

                
        print('Storing wordlists to %s' % self.wordlistDir)
        self.storeWordlist(self.paths, 'paths.txt')
        self.storeWordlist(self.keys, 'keys.txt')
        self.storeWordlist(self.values, 'values.txt')
        self.storeWordlist(self.queries, 'queries.txt')
        self.storeWordlist(self.subdomains, 'subdomains.txt')
        print('Done!')

    def processPath(self, url):
        '''
        Extract path from URL.
        Assumes that the url is properly UTF-8 encoded.
        '''
        path = urlparse(url).path
        self.paths.add(path)
    
    def processSubdomain(self, url):
        '''
        Get subdomains from URL. E.g.
        acc.v1.website.com => acc.v1
        Assumes that the url is properly UTF-8 encoded.
        '''
        subdomain = '.'.join(urlparse(url).netloc.split('.')[:-2])
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
        
        key = self._helpers.bytesToString(param.getName()).encode('utf-8')
        value = self._helpers.bytesToString(param.getValue()).encode('utf-8')
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

