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
from ..plugin import *
from ..http import *
from ..kb import *
from threading import Lock
from subprocess import Popen

class SqlMap(Plugin):
	def __init__( self, pm ):
		Plugin.__init__( self, "sqlmap", "Simone Margaritelli <evilsocket@gmail.com>", "This module will ask the user to launch sqlmap when a sql injection is found." )
		self.pm = pm
		
	def onVulnerabilityFound( self, target, kbitem, parameter ):
		if kbitem.id == "sqli":
			resp = raw_input( "[!] A sql injection was found on '%s', do you want me to spawn a sqlmap instance to exploit it ? [yN]" % target.url.path )
			if resp.strip() != '' and resp in "Yy":
				Popen( "sqlmap -u '%s' -o --threads 30 --text-only --dbs -p %s" % (target.url.get(), parameter), shell = True, executable = "/bin/bash" ).wait()
