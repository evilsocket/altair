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
from core.html import Parser
from core.http import *
from core.kb import *
from core.scanner import Scanner
from core.edispatcher import EventDispatcher
from core.plugin import PluginManager
import sys
import re
import os
from optparse import OptionParser, OptionGroup 

def csv2array( csv ):
	items = csv.split(',')
	res   = []
	for i, item in enumerate(items):
		item = item.strip()
		if item != '':
			res.append(item)
	return res

# nasty hack to have the setdefaultencoding function available
reload(sys)
sys.setdefaultencoding('utf8')

print "\n --------------------------------------------------------\n" + \
	  "|    Altair 1.0 - A Modular Web Vulnerability Scanner    |\n" + \
	  "| Copyleft by Simone Margaritelli <evilsocket@gmail.com> |\n" + \
	  "|   http://www.evilsocket.net - http://www.backbox.org   |\n" + \
	  " --------------------------------------------------------\n"

parser = OptionParser( usage = "usage: %prog [options] -u <target>\n\n" +
                               "EXAMPLES:\n" +
                               "  %prog --filter=lfi,rfi --url=http://www.somesite.com\n" +
                               "  %prog --filter=sqli --load-modules=sqlmap --url=http://www.somesite.com" )

path   = os.path.dirname(os.path.realpath(__file__))

parser.add_option( "-t", "--threads",      action="store",      dest="Threads", 	      default=50,		   help="Max simultaneous threads." )
parser.add_option( "-e", "--ext", 	       action="store",      dest="AllowedExtensions", default="cgi,cfm,asp,aspx,php,php2,php3,php4,php5,htm,html,shtm,shtml,jsp,do,py", help="Comma separated allowed extensions." )
parser.add_option( "-a", "--ua", 	       action="store",      dest="UserAgent",         default=None, 	   help="Custom user agent." )
parser.add_option( "-d", "--enable-delay", action="store_true", dest="CrawlDelayEnabled", default=False,	   help="Enable crawling delay." )
parser.add_option( "-s", "--crawl-delay",  action="store",      dest="CrawlDelay",        default=100, 		   help="Crawling delay in ms." )
parser.add_option( "-m", "--max-depth",    action="store",      dest="MaxDirectoryDepth", default=10,		   help="Max directory depth." )
parser.add_option( "-p", "--enable-proxy", action="store_true", dest="ProxyEnabled",      default=False,	   help="Enable proxy support." )
parser.add_option( "-S", "--proxy-server", action="store",      dest="ProxyServer",       default="localhost", help="Proxy server address." )
parser.add_option( "-P", "--proxy-port",   action="store",      dest="ProxyPort",         default=9051,		   help="Proxy server port." )
parser.add_option( "-f", "--filter",       action="store",      dest="KbFilter",          default='*',         help="Comma separated ids of vulnerabilities to test, default to all, use the --list-ids flag to enumerate available ids." )
parser.add_option( "-I", "--list-ids",	   action="store_true", dest="IdList",            default=False,       help="Print a list of available ids in the knowledge base to be used with the --filter flag." )
parser.add_option( "-k", "--kb", 	       action="store",      dest="KbFile",            default="%s/kb.xml" % path, help="Knowledge base file to use, default kb.xml." )
parser.add_option( "-L", "--load-modules", action="store",		dest="Modules", 		  default='',		   help="Comma separated modules names to load or 'all' to load them all, use the --list-modules flag to a list of available modules." )
parser.add_option( "-M", "--list-modules", action="store_true", dest="ModList",           default=False,       help="Print a list of available modules." )
parser.add_option( "-u", "--url",          action="store",      dest="url",               default=None, 	   help="Url to test, mandatory." )

(o,args) = parser.parse_args()


if o.IdList == True:
	kb = KnowledgeBase( o.KbFile, ['*'] )
	for item in kb.items:
		if item.id != '*':
			print "[%s] %s :\n%s\n" % (item.id, item.name, item.description)
	quit()
elif o.ModList == True:
	pm = PluginManager( "%s/core/modules" % path, None )
	pm.loadPlugins()
	for plugin in pm.plugins:
		print "[+] '%s' by %s : %s" % (plugin.name, plugin.author, plugin.description)
	quit()

if o.url == None:
	parser.error( "No url specified!" )
elif not re.match( '^[^\:]+\:\/\/.+$', o.url ):
	o.url = "http://" + o.url

o.Threads			= int(o.Threads)
o.CrawlDelay		= int(o.CrawlDelay)
o.MaxDirectoryDepth = int(o.MaxDirectoryDepth)
o.ProxyPort			= int(o.ProxyPort)
o.KbFilter   		= csv2array(o.KbFilter)
o.AllowedExtensions = csv2array(o.AllowedExtensions)
o.Modules			= csv2array(o.Modules)

ed = EventDispatcher(None)
pm = PluginManager( "core/modules" % path, ed )
ed.pmanager = pm

pm.loadPlugins( o.Modules )

ed.status( "Loading the knowledge base from %s ..." % o.KbFile )
kb      = KnowledgeBase( o.KbFile, o.KbFilter )
root    = Url( o.url )
docrawl = False

for filter in o.KbFilter:
	if filter != 'files' and filter != 'dirs':
		docrawl = True
		break

if docrawl == True:
	ed.status( "Starting crawling process on %s ..." % o.url )
	parser  = Parser( root, o, ed )
	targets = []
	parser.parse( GetRequest( root ) )
 
	for req in parser.requests:
		if req.fields != {} or req.url.params != {}:
			targets.append(req)
			
	ed.status( "Found %d targets ." % len(targets) )
else:
	ed.warning( "Skipping crawling process ." )
	targets = [ GetRequest(root) ]
	
try:
	scanner = Scanner( kb, o, targets, ed )
	
	ed.status( "Running vulnerability scanner ..." )
	
	scanner.start()
except KeyboardInterrupt:
	ed.warning( "Stopping the scanner ..." )
	scanner.stop()