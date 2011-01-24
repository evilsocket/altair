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
from http import *
from kb import *
from plugin import PluginManager
from threading import Lock

class EventDispatcher:
	def __init__( self, output, pm ):
		self.output		 = output
		self.pmanager 	 = pm
		self.print_mutex = Lock()
		
	def __to_file( self, txt ):
		fd = file( self.output, "at" )
		fd.write( txt )
		fd.close()
		
	def status( self, txt ):
		self.print_mutex.acquire()
		if self.output == None:
			print "[@] %s" % txt
		else:
			self.__to_file( "[@] %s\n" % txt )
		self.print_mutex.release()
		
	def warning( self, txt ):
		self.print_mutex.acquire()
		if self.output == None:
			print "\033[1;33m[@] %s\033[1;m" % txt
		else:
			self.__to_file( "[W] %s\n" % txt )
		self.print_mutex.release()
		
	def parsing( self, url ):
		self.print_mutex.acquire()
		if self.output == None:
			print "[@] Crawling \033[1;32m%s\033[1;m" % url.get()
		else:
			self.__to_file( "[@] Crawling %s\n" % url.get() )
		self.print_mutex.release()
		for plugin in self.pmanager.plugins:
			plugin.onUrlCrawling( url )
		
	def stopped( self, target ):
		self.print_mutex.acquire()
		self.status( "Scanning process finished ." )
		for plugin in self.pmanager.plugins:
			plugin.onScanFinished(target)
		self.print_mutex.release()
		
	def vulnerability( self, target, kbitem, parameter ):
		self.print_mutex.acquire()
		if self.output == None:
			if isinstance( target, GetRequest ):
				print "[!] Found \033[1;31m'%s'\033[1;m on \033[1;31m%s\033[1;m !" % ( kbitem.name, target.dyn_url.get() )	
			else:
				print "[!] Found \033[1;31m'%s'\033[1;m on \033[1;31m%s\033[1;m :" % ( kbitem.name, target.dyn_url.get() )	
				for name, value in target.dyn_fields.items():
					print "\t%s : \033[1;31m%s\033[1;m" % (name,value)
		else:
			if isinstance( target, GetRequest ):
				self.__to_file( "[!] Found '%s' on %s !\n" % ( kbitem.name, target.dyn_url.get() ) )	
			else:
				self.__to_file( "[!] Found '%s' on %s !\n" % ( kbitem.name, target.dyn_url.get() ) )	
				for name, value in target.dyn_fields.items():
					self.__to_file( "\t%s : %s\n" % (name,value) )

		for plugin in self.pmanager.plugins:
			plugin.onVulnerabilityFound( target, kbitem, parameter )
			
		self.print_mutex.release()