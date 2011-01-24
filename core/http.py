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
from urllib import quote, unquote, urlencode
import urlparse
import urllib2
import unicodedata
import re
import os

class Url:
	def __init__( self, url, default_netloc = '', default_scheme = 'http', default_path = '/' ):
		p = urlparse.urlparse(url)
		self.scheme = p.scheme if p.scheme != '' else default_scheme
		self.netloc = p.netloc if p.netloc != '' else default_netloc
		self.path   = p.path   if p.path   != '' else default_path 
		self.params = {}
		self.query  = p.query
		
		# decode
	 	if isinstance( self.path, unicode ):
	 		self.path = unicodedata.normalize( 'NFKD', self.path ).encode('ascii','ignore')

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
			self.params = {}
			args  		= urlparse.parse_qs( unquote(self.query) )
			for k,v in args.items():
				self.params[k] = v[0]
			
	def copy( self ):
		return Url( self.get(), self.netloc, self.scheme, self.path )
		
	def __composeQuery( self ):
		kvs = []
		for k, v in self.params.items():
			kvs.append( "%s=%s" % ( quote( k ), quote( v ) ) )	
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
		elif self.params.keys().sort() != url.params.keys().sort():
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
		elif self.fields.keys().sort() != req.fields.keys().sort():
			return False
		else:
			return True
			
	def fetch( self ):
		req    = urllib2.Request( self.dyn_url.get(), urlencode(self.dyn_fields) if self.dyn_fields != {} else None, self.headers )
		opener = urllib2.build_opener( RedirectHandler() )
		res    = opener.open(req)
		resp   = res.read()
		
		if res.url != ("%s://%s%s" % ( self.url.scheme, self.url.netloc, self.url.path )):
			self.redirect = res.url
		else:
			self.redirect = None
			
		# extract charset
		charset = re.findall( "\s+charset\s*\=\s*([^'\"]+)\s*", resp )
		if len(charset):
			charset = charset[0]
		else:
			charset = 'UTF-8'
		
		# i know, don't tell me!
		encodings = [  charset, "ascii", "utf_8", "big5", "big5hkscs", "cp037", "cp424", "cp437", "cp500", "cp737", "cp775", "cp850", "cp852", "cp855", 
					   "cp856", "cp857", "cp860", "cp861", "cp862", "cp863", "cp864", "cp865", "cp866", "cp869", "cp874", "cp875", "cp932", "cp949", 
					   "cp950", "cp1006", "cp1026", "cp1140", "cp1250", "cp1251", "cp1252", "cp1253", "cp1254", "cp1255", "cp1256", "cp1257", "cp1258", 
					   "euc_jp", "euc_jis_2004", "euc_jisx0213", "euc_kr", "gb2312", "gbk", "gb18030", "hz", "iso2022_jp", "iso2022_jp_1", "iso2022_jp_2", 
					   "iso2022_jp_2004", "iso2022_jp_3", "iso2022_jp_ext", "iso2022_kr", "latin_1", "iso8859_2", "iso8859_3", "iso8859_4", "iso8859_5", 
					   "iso8859_6", "iso8859_7", "iso8859_8", "iso8859_9", "iso8859_10", "iso8859_13", "iso8859_14", "iso8859_15", "johab", "koi8_r", "koi8_u", 
					   "mac_cyrillic", "mac_greek", "mac_iceland", "mac_latin2", "mac_roman", "mac_turkish", "ptcp154", "shift_jis", "shift_jis_2004", 
					   "shift_jisx0213", "utf_32", "utf_32_be", "utf_32_le", "utf_16", "utf_16_be", "utf_16_le", "utf_7", "utf_8_sig" ]		
		
		decoded = ""
		for encoding in encodings:
			try:
				decoded = unicode( resp, encoding )
				if decoded:
					return decoded
			except UnicodeDecodeError as e:
				pass
		
		return decoded
		
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
