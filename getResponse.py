#load  contextmenu factory
# get selected request
# make request and retrieve response(iBurpExtenderCallbacks.makeHttpRequest () ) 
# insert response to sitemap # addToSiteMap(IHttpRequestResponse item)

#burp imports
from burp import IBurpExtender
from burp import IContextMenuFactory

#Java imports
from javax.swing import JMenuItem
from java.util import List,ArrayList
from java.net import URL

#python imports
import threading 

class BurpExtender(IBurpExtender,IContextMenuFactory):
	def registerExtenderCallbacks(self,callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()
		self.callbacks.setExtensionName("Site map fetcher modified")
		self.callbacks.registerContextMenuFactory(self)
		self.user_agent = 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
		self.max_redirect = 4
		return


	def createMenuItems(self, IContextMenuInvocation):
		self.selectedRequest = IContextMenuInvocation.getSelectedMessages()
		menuItemList = ArrayList()
		menuItemList.add(JMenuItem("Refresh this site map entry with new request (no cookies)", actionPerformed = self.onClickNoCookies))
		menuItemList.add(JMenuItem("Refresh this site map entry with new request (add cookies from jar)", actionPerformed = self.onClickCookies))
		return menuItemList


	def makeRequest(self, service, request, redirect=False, rd_count=0, replace_redirect=False):
		rsp = self.callbacks.makeHttpRequest(service, request)
		self.callbacks.addToSiteMap(rsp)
		if redirect and rd_count < self.max_redirect:
			rsp_a = self.helpers.analyzeResponse(rsp.getResponse())
			if rsp_a.getStatusCode() == 302:
				l = [a for a in rsp_a.getHeaders() if a.startswith('Location: /')] # only onsite redirects
				location = l[0].split(':', 1)[1].lstrip() if l else None
				if location:
					sm_entries = self.callbacks.getSiteMap(location)
					if replace_redirect and len(sm_entries) > 0 and sm_entries[0].getResponse() and len(sm_entries[0].getResponse()) > 0: # only redirects not already in sitemap
						rd_count+=1
						nr = bytearray('GET %s' %(location), 'utf-8') + request[request.index(' HTTP'):]
						self.makeRequest(service, nr, redirect=True, rd_count=rd_count)
					else:
						print 'Redirect location %s already in site map, will not replace' %(location)


	def onClickNoCookies(self,event):
		for item in self.selectedRequest:
			if(len(self.helpers.analyzeRequest(item).getParameters()) > 0):
				t = threading.Thread(target=self.makeRequest,args=[item.getHttpService(), item.getRequest()])
				t.daemon = True
				t.start()
			else:
				if(self.helpers.analyzeRequest(item).getUrl().toString()[-1:] == "/"):
					t = threading.Thread(target=self.makeRequest,args=[item.getHttpService(), item.getRequest()])
					t.daemon = True
					t.start()


	def onClickCookies(self,event):
		cookies = self.callbacks.getCookieJarContents()
		for request in self.selectedRequest:
			analysed_item = self.helpers.analyzeRequest(request)
			hostname = analysed_item.getUrl().toString().split('//', 1)[1].split(':', 1)[0]
			url = '/' + analysed_item.getUrl().toString().split(hostname, 1)[1].split('/', 1)[1]
			add_cookies = {}
			for cookie in cookies:
				cp = '' if not cookie.getPath() else cookie.getPath()
				if cookie.getDomain() in hostname and (cp == '' or (len(cp) > 0 and url.startswith(cp))):
					add_cookies[cookie.getName()] = cookie.getValue()

			
			offset = analysed_item.getBodyOffset()
			request_bytes = request.getRequest()
			body = request_bytes[offset:]
			http_command = [request_bytes[:offset].tostring().split('\r\n')[0]]
			http_headers = [a for a in request_bytes[:offset].tostring().split('\r\n')[1:] if a and not a.startswith('Cookie:')] # cookie header will be recreated
			if not [a for a in http_headers if a.startswith('User-Agent:')]:
				http_headers.append('User-Agent: %s' %(self.user_agent))
			new_cookies = 'Cookie: %s\r\n' %('; '.join(['%s=%s' %(a, add_cookies[a]) for a in add_cookies]))
			http_headers.append(new_cookies)

			nr = bytearray('\r\n'.join(http_command + http_headers) + '\r\n', 'utf-8') + bytearray(body)

			t = threading.Thread(target=self.makeRequest,args=[request.getHttpService(), nr], kwargs={'redirect':True})
			t.daemon = True
			t.start()

