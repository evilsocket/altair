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
import os
from http import *

class Plugin:
	def __init__( self, name, author, description ):
		self.name   	 = name
		self.author 	 = author
		self.description = description
	
	def onUrlCrawling( self, url ):
		pass
		
	def onVulnerabilityFound( self, target, kbitem ):
		pass
		
	def onScanFinished( self, target ):
		pass
	
class PluginManager:
	def __init__( self, path, edispatcher ):
		self.path	 = path
		self.plugins = []
		self.ed		 = edispatcher
	
	def loadPlugins( self, filter = ['all'] ):
		# tnx to LuckyDonkey <http://www.luckydonkey.com/> for this :)
		for root, dirs, files in os.walk(self.path):
			for name in files:
				if name.endswith(".py") and not name.startswith("__"):
					path 	   = os.path.join(root, name)
					modulename = "core.modules" + path.rsplit( 'core/modules' )[1].rsplit('.',1)[0].replace('/','.')
					module	   = __import__(modulename)
					# walk the dictionaries to get to the last one
					d = module.__dict__
					for m in modulename.split('.')[1:]:
						d = d[m].__dict__
       				# look through this dictionary for things
        			# that are subclass of Plugin but are not Plugin itself
					for key, entry in d.items():
						if key == Plugin.__name__:
							continue
						try:
							if issubclass( entry, Plugin ):
								plugin = entry( self )
								if 'all' in filter or plugin.name in filter:
									if self.ed != None:
										self.ed.status( "Loading module '%s' ." % plugin.name )
									self.plugins.append( plugin )
						except TypeError:
							# this happens when a non-type is passed in to issubclass. We
							# don't care as it can't be a subclass of Plugin if it isn't a
							# type
							continue