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
	def __init__( self, pm ):
		self.pmanager 	 = pm
		self.print_mutex = Lock()
		
	def status( self, txt ):
		self.print_mutex.acquire()
		print "[@] %s" % txt
		self.print_mutex.release()
		
	def warning( self, txt ):
		self.print_mutex.acquire()
		print "\033[1;33m[@] %s\033[1;m" % txt
		self.print_mutex.release()
		
	def parsing( self, url ):
		self.print_mutex.acquire()
		print "[@] Crawling \033[1;32m%s\033[1;m" % url.get()
		self.print_mutex.release()
		for plugin in self.pmanager.plugins:
			plugin.onUrlCrawling( url )
		
		
	def vulnerability( self, target, kbitem, parameter ):
		self.print_mutex.acquire()
		if isinstance( target, GetRequest ):
			print "[!] Found \033[1;31m'%s'\033[1;m on \033[1;31m%s\033[1;m !" % ( kbitem.name, target.dyn_url.get() )	
		else:
			print "[!] Found \033[1;31m'%s'\033[1;m on \033[1;31m%s\033[1;m :" % ( kbitem.name, target.dyn_url.get() )	
			for name, value in target.dyn_fields.items():
				print "\t%s : \033[1;31m%s\033[1;m" % (name,value)
		
		for plugin in self.pmanager.plugins:
			plugin.onVulnerabilityFound( target, kbitem, parameter )
			
		self.print_mutex.release()