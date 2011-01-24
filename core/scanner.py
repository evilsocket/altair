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
from html import Parser
from http import *
from kb import *
from edispatcher import EventDispatcher
from threadpool import ThreadPool
from threading import Thread
from urllib2 import HTTPError
import random
import httplib

class HttpVerifierThread(Thread):
	def __init__( self, kbitem, payload, target, edispatcher, resp404 ):
		Thread.__init__(self)
		self.kbitem	 = kbitem
		self.payload = payload
		self.target  = target
		self.ed		 = edispatcher
		self.resp404 = resp404
		
	def run( self ):				
		url    = Url( self.payload.data, self.target.url.netloc, self.target.url.scheme, '/' )
		target = GetRequest(url)
		
		try:
			response = target.fetch()
			if self.resp404 == None or response != self.resp404:	
				self.ed.vulnerability( target, self.kbitem, None )
		except:
			pass

class ScannerThread(Thread):
	def __init__( self, kbitem, target, edispatcher ):
		Thread.__init__(self)
		self.kbitem = kbitem
		self.target = target
		self.ed	    = edispatcher
		
	def __genRandom( self ):
		rand = ''
		for i in range(10):
			rand += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
		return rand
		
	def run( self ):
			if self.kbitem.id in ( 'files', 'dirs' ):
				resp404 = None 
				try:
					non_existent_url      = target.url.copy()
					non_existent_url.path =  "/%s" % self.__genRandom()
					non_existent          = GetRequest(non_existent_url)
					resp404				  = non_existent.fetch()
				except:
					pass
				
				pool = ThreadPool( window_size = 20, prototype = HttpVerifierThread )
				for payload in self.kbitem.payloads:
					pool.pushArgs( self.kbitem, payload, self.target, self.ed, resp404 )
					
				pool.start()
			else:
				for payload in self.kbitem.payloads:
					try:
						random = self.__genRandom()
						if (payload.scope == '*' or payload.scope.lower() == 'get') and isinstance( self.target, GetRequest ):
							for param in self.target.url.params.keys():
								target = self.target.copy()
								target.__class__ = GetRequest
								p 	   = payload.copy()
								if "@RANDOM" in p.data:
									p.data = p.data.replace( "@RANDOM", random )
									
								target.setParam( param, p.data )
								
								response = target.fetch()
								
								for m in self.kbitem.matches:
									m = m.copy()
									if "@PAYLOAD" in m.data:
										m.data = m.data.replace( "@PAYLOAD", p.data )
									if "@RANDOM" in m.data:
										m.data = m.data.replace( "@RANDOM", random )
									if m.match(response):
										self.ed.vulnerability( target, self.kbitem, param )
										return
						elif (payload.scope == '*' or payload.scope.lower() == 'post') and isinstance( self.target, PostRequest ):
							for field in self.target.fields.keys():
								target = self.target.copy()
								target.__class__ = PostRequest
								p 	   = payload.copy()
								if "@RANDOM" in p.data:
									p.data = p.data.replace( "@RANDOM", random )
									
								target.setField( field, p.data )
								
								response = target.fetch()
								
								for m in self.kbitem.matches:
									m = m.copy()
									if "@PAYLOAD" in m.data:
										m.data = m.data.replace( "@PAYLOAD", p.data )
									if "@RANDOM" in m.data:
										m.data = m.data.replace( "@RANDOM", random )
									if m.match(response):
										self.ed.vulnerability( target, self.kbitem, field )
										return
							for param in self.target.url.params.keys():
								target = self.target.copy()
								target.__class__ = PostRequest
								p 	   = payload.copy()
								if "@RANDOM" in p.data:
									p.data = p.data.replace( "@RANDOM", random )
									
								target.setParam( param, p.data )
								
								response = target.fetch()
								
								for m in self.kbitem.matches:
									m = m.copy()
									if "@PAYLOAD" in m.data:
										m.data = m.data.replace( "@PAYLOAD", p.data )
									if "@RANDOM" in m.data:
										m.data = m.data.replace( "@RANDOM", random )
									if m.match(response):
										self.ed.vulnerability( target, self.kbitem, param )
										return
						elif payload.scope.lower() == 'header':
							target 	   = self.target.copy()
							connection = httplib.HTTPConnection( target.url.netloc )
							connection.request( "HEAD", "/" )
							response = connection.getresponse()
							headers  = response.getheaders()
							for header in headers:
								for m in self.kbitem.matches:
									if m.match(header[1]):
										self.ed.vulnerability( target, self.kbitem, None )
										return
					# except HTTPError as e:
					#	self.ed.warning(e)
					except:
						pass
		
class Scanner:
	def __init__( self, kb, cfg, targets, edispatcher ):
		self.kb      = kb
		self.cfg     = cfg
		self.targets = targets
		self.pool	 = ThreadPool( window_size = self.cfg.Threads, prototype = ScannerThread, async = False )
		self.ed		 = edispatcher
		
	def start( self ):
		for target in self.targets:
			for kbitem in self.kb.items:
				self.pool.pushArgs( kbitem, target, self.ed )
				
		self.pool.start()
		
	def stop( self ):
		self.pool.stop()
		
	def running( self ):
		return self.pool.active