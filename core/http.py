#!/usr/bin/python
# This file is part of Altair web vulnerability scanner.
#
# Copyright(c) 2010-2011 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
# http://www.backbox.org
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from urlparse import urlparse
from urllib import quote, unquote, urlencode
import urllib2
import re
import os

class Url:
	def __init__( self, url, default_netloc = '', default_scheme = 'http', default_path = '/' ):
		p = urlparse(url)
		self.scheme = p.scheme if p.scheme != '' else default_scheme
		self.netloc = p.netloc if p.netloc != '' else default_netloc
		self.path   = p.path   if p.path   != '' else default_path 
		self.params = {}
		self.query  = p.query
		
		# remove default net location from path
		if self.netloc in self.path:
			self.path = self.path.replace( self.netloc, '' )
			
		# fix path
		if self.path[0] != '/':
			if re.match( '^.+\.[^\.]+$', self.path ):
				self.path = os.path.split(default_path)[0] + "/" + self.path
			else:
				self.path = default_path + "/" + self.path
		
		# fix relative path
		if '.' in self.path:
			tree = filter( str.strip, self.path.split('/') )
			path = []
			for item in tree:
				if item == '.':
					pass
				elif item == '..':
					if len(path): path.pop()
				else:
					path.append(item)
			
			self.path = "/%s" % "/".join(path)
						
		# split and parse params
		if self.query != '':
			self.__parseQuery()
			
	def copy( self ):
		return Url( self.get(), self.netloc, self.scheme, self.path )
	
	def __parseQuery( self ):
		self.params = {}
		kvals 	    = self.query.split('&')
		for kval in kvals:
			if '=' in kval:
				(key, value) = kval.split('=',2)
				self.params[key] = quote( unquote(value) )
			else:
				self.params[kval] = ''
			
	def __composeQuery( self ):
		kvs = []
		for k, v in self.params.items():
			# i know it seems stupid to unquote and quote, but i don't know for sure
			# if k or v are already quoted, so i unquote them just to be sure :)
			kvs.append( "%s=%s" % ( quote( unquote(k) ), quote( unquote(v) ) ) )	
		self.query = "&".join(kvs)
	
	def __ne__ ( self, url ):
		return not self.__eq__( url )
	
	def __eq__ ( self, url ):
		if self.scheme != url.scheme:	
			return False
		elif self.netloc != url.netloc:
			return False
		elif self.path != url.path:
			return False
		elif self.params.keys() != url.params.keys():
			return False
		else:
			return True 
			
	def get( self ):
		self.__composeQuery()
		return "%s://%s%s%s%s" % ( self.scheme, self.netloc, self.path, '?' if self.query != '' else '', self.query )
	
	def __str__( self ):
		return "URL ( scheme = %s, netloc = %s, path = %s, params = %s, query = %s)" % (self.scheme,self.netloc,self.path,self.params,self.query)

class RedirectHandler(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        m = req.get_method()
        if (code in (301, 302, 303, 307) and m in ("GET", "HEAD") or code in (301, 302, 303) and m == "POST"):
            newurl = newurl.replace(' ', '%20')
            newheaders = dict((k,v) for k,v in req.headers.items()
                              if k.lower() not in ("content-length", "content-type")
                             )
            
            return urllib2.Request( newurl,
                            headers = newheaders,
                            origin_req_host=req.get_origin_req_host(),
                            unverifiable=True)
        else:
            raise HTTPError(req.get_full_url(), code, msg, headers, fp)
            
class Request:
	def __init__( self, url ):
		self.type		= 0
		self.url        = url.copy()
		self.dyn_url    = url.copy()
		self.redirect   = None
		self.headers    = {}
		self.fields	    = {}
		self.dyn_fields = {}
	
	def copy( self ):
		req 		   = Request( self.url )
		req.type       = self.type
		req.headers    = self.headers.copy()
		req.fields     = self.fields.copy()
		req.dyn_fields = self.dyn_fields.copy()
		return req
	
	def setProxy( self, address, port ):
		proxy  = urllib2.ProxyHandler( {"http" : "http://%s:%d" % (address,port) } )
		opener = urllib2.build_opener( proxy )
		urllib2.install_opener(opener)
	
	def setParam( self, name, value ):
		self.dyn_url.params[name] = value
	
	def addField( self, name, value ):
		self.fields[name] = value
		self.dyn_fields[name] = value
		
	def setField( self, name, value ):
		self.dyn_fields[name] = value
	
	def setHeader( self, name, value ):
		self.headers[name] = value
		
	def reset( self ):
		self.dyn_url    = self.url.copy()
		self.dyn_fields = self.fields.copy()
		
	def __ne__ ( self, req ):
		return not self.__eq__( req )
		
	def __eq__( self, req ):
		if self.type != req.type:
			return False
		if self.url != req.url:
			return False
		elif self.fields != req.fields:
			return False
		else:
			return True
			
	def fetch( self ):
		self.redirect = None
		req    = urllib2.Request( self.dyn_url.get(), urlencode(self.dyn_fields) if self.dyn_fields != {} else None, self.headers )
		opener = urllib2.build_opener( RedirectHandler() )
		res    = opener.open(req)
		resp   = res.read()
	
		if res.url != ("%s://%s%s" % ( self.url.scheme, self.url.netloc, self.url.path )):
			self.redirect = res.url
			
		# extract charset
		charset = re.findall( "\s+charset\s*\=\s*([^'\"]+)\s*", resp )
		if len(charset):
			charset = charset[0]
		else:
			charset = 'UTF-8'
			
		return unicode( resp, charset )
		
class GetRequest(Request):
	def __init__( self, url ):
		Request.__init__( self, url )
		self.type = 1
		
	def __str__( self ):
		return "GET : %s" % self.url
	
class PostRequest(Request):
	def __init__( self, url ):
		Request.__init__( self, url )
		self.type = 2
		
	def __str__( self ):
		return "POST %s : %s" % ( self.fields, self.url )
