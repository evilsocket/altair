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
from HTMLParser import HTMLParser, HTMLParseError
from http import Url, GetRequest, PostRequest
from edispatcher import EventDispatcher
from urllib2 import HTTPError
from urllib import *
import os
import re
import time
from thirdparties.BeautifulSoup import BeautifulSoup

class Parser(HTMLParser):
	def __init__( self, root, config, edispatcher ):
		HTMLParser.__init__(self)
		self.scheme   = root.scheme
		self.domain	  = root.netloc
		self.root	  = root
		self.config   = config
		self.requests = []
		self.parsed	  = []
		self.form	  = None
		self.ed		  = edispatcher
		self.current  = None
		
	def parse( self, request ):
		# check for a valid extension
		if self.config.AllowedExtensions != None:
			( root, ext ) = os.path.splitext( request.url.path )
			if ext[1:] not in self.config.AllowedExtensions and ext != '':
				self.ed.warning( "Skipping page with unallowed extension '%s' ." % request.url.path )
				self.parsed.append( request )
				return
		# check directory depth
		if self.config.MaxDirectoryDepth != None:
			if len(request.url.path.split('/')) + 1 > self.config.MaxDirectoryDepth:
				self.ed.warning( "Max directory depth exceeded '%s' ." % request.url.path )
				self.parsed.append( request )
				return
		# if enabled, delay the crawl process
		if self.config.CrawlDelayEnabled != None and self.config.CrawlDelayEnabled == True:
			self.ed.warning( "Delaying crawling process of %d ms ..." % self.config.CrawlDelay )
			time.sleep( self.config.CrawlDelay / 1000.0 )
		
		try:
			# set user-agent if specified
			if self.config.UserAgent != None:
				request.setHeader( 'User-Agent', self.config.UserAgent )
			# set proxy if specified
			if self.config.ProxyEnabled != None and self.config.ProxyEnabled == True:
				self.ed.status( "Setting request proxy to %s:%d ." % ( self.config.ProxyServer, self.config.ProxyPort ) )
				request.setProxy( self.config.ProxyServer, self.config.ProxyPort )
		
			response = request.fetch()
			# fix broken html
			response = re.sub( "href\s*=\s*([^\"'\s>]+)" , r'href="\1"', response )
			response = re.sub( "src\s*=\s*([^\"'\s>]+)" , r'src="\1"', response )
			response = re.sub( "action\s*=\s*([^\"'\s>]+)" , r'action="\1"', response )
			response = re.sub( "method\s*=\s*([^\"'\s>]+)" , r'method="\1"', response )
			response = re.sub( "name\s*=\s*([^\"'\s>]+)" , r'name="\1"', response )
			response = re.sub( "value\s*=\s*([^\"'\s>]+)" , r'value="\1"', response )
			
			response = BeautifulSoup(response).prettify()
						
			self.current = request.url
			
			self.ed.parsing( request.url )
			
			self.feed( response )
			self.close()
			
			# custom parsing
			pages = re.findall( 'window\.open\s*\(\s*[\'"]([^\'"]+)',  response )
			if pages != None:
				for page in pages:
					url = Url( page, default_netloc = self.domain, default_path = self.root.path )
					if url.netloc == self.domain and url.scheme == self.scheme:
						req = GetRequest( url )
						if req not in self.requests:
							self.requests.append( req )
		except HTTPError as e:	
			self.ed.warning( "%s (%s)" % (request.url.get(),e) )
		except Exception as e:
			self.ed.warning( e )
		finally:
			self.parsed.append( request )
			if request.redirect != None:
				url = Url( request.redirect, default_netloc = self.domain, default_path = self.root.path )
				self.parsed.append( GetRequest(url) )
		
		for req in self.requests:
			if req not in self.parsed:
				self.parse( req )
				
	def __get_attr( self, name, attrs, default = '' ):
		for a in attrs:
			aname = a[0].lower()
			if aname == name:
				return a[1]
		return default
		
	def __sameDomain( self, domain ):
		return re.match( ".*\.?%s" % re.escape(self.domain), domain ) or re.match( ".*\.?%s" % re.escape(domain), self.domain )
	
	def handle_starttag( self, tag, attrs ):
		tag = tag.lower()
		if tag == 'a':
			href = self.__get_attr( 'href', attrs )
			url  = Url( href, default_netloc = self.domain, default_path = self.current.path )				
			if self.__sameDomain(url.netloc) and url.scheme == self.scheme:
				req = GetRequest( url )
				if req not in self.requests:
					self.requests.append( req )
		elif tag == 'img':
			src = self.__get_attr( 'src', attrs )
			for ext in self.config.AllowedExtensions:
				if re.match( ".+\.%s.*" % ext, src ):
					url = Url( src, default_netloc = self.domain, default_path = self.current.path )
					if self.__sameDomain(url.netloc) and url.scheme == self.scheme:
						req = GetRequest( url )
						if req not in self.requests:
							self.requests.append( req )
							break
		elif tag == 'frame' or tag == 'iframe':
			src = self.__get_attr( 'src', attrs )
			url = Url( src, default_netloc = self.domain, default_path = self.current.path )
			if self.__sameDomain(url.netloc) and url.scheme == self.scheme:
				req = GetRequest( url )
				if req not in self.requests:
					self.requests.append( req )
		elif tag == 'form':
			self.form 		    = {}
			self.form['data']   = {}
			self.form['action'] = self.__get_attr( 'action', attrs, self.current.path )
			self.form['method'] = self.__get_attr( 'method', attrs, 'get' ).lower()
		elif self.form != None:
			if tag == 'input':
				name  = self.__get_attr( 'name',  attrs )
				value = self.__get_attr( 'value', attrs )
				self.form['data'][name] = value
			elif tag == 'select':
				self.form['data'][self.__get_attr( 'name',  attrs )] = ''
				
	def handle_endtag( self, tag ):
		tag = tag.lower()
		if tag == 'form' and self.form != None:
			if self.form['method'] == 'get':
				link = self.form['action'] + "?" + urlencode( self.form['data'] )
				url  = Url( link, default_netloc = self.domain )
				if self.__sameDomain(url.netloc) and url.scheme == self.scheme:
					req = GetRequest( url )
					if req not in self.requests:
						self.requests.append( req )
			elif self.form['method'] == 'post':
				link = self.form['action']
				url  = Url( link, default_netloc = self.domain, default_path = self.current.path )
				if self.__sameDomain(url.netloc) and url.scheme == self.scheme:
					req = PostRequest(url)
					for name, value in self.form['data'].items():
						req.addField( name, value )
					if req not in self.requests:
						self.requests.append( req )
				
			self.form = None