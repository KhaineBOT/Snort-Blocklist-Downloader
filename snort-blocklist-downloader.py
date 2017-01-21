import urllib2
import re
import sys, argparse
import subprocess, shlex

#blocklist information

blocklists = {
	'abuse.ch Zeus Tracker': {
		'id': 'abusezeus',
		'url':  'https://zeustracker.abuse.ch/blocklist.php?download=snort',
		'regex' : '',
		'file' : 'zeus.rules',
	},
	'abuse.ch Feodo Tracker': {
		'id': 'abusefeodo',
		'regex': '',
		'url':  'https://feodotracker.abuse.ch/blocklist/?download=snort',
		'file': 'palevo.rules',
	},
	'abuse.ch SSL Blacklist Tracker': {
		'id': 'abusesslbl',
		'regex': '',
		'url':  'https://sslbl.abuse.ch/blacklist/sslipblacklist.rules',
		'file': 'sslipblacklist.rules',
	},
	'abuse.ch Dyre SSL Blacklist Tracker': {
		'id': 'abusedyresslbl',
		'regex': '',
		'url':  'https://sslbl.abuse.ch/blacklist/dyre_sslipblacklist.rules',
		'file': 'dyre_sslipblacklist.rules',	
	},
	'Emerging threats botcc': {
		'id': 'emerging-botcc',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-botcc.rules',
		'file': 'emerging-botcc.rules',	
	},
	'Emerging threats botcc-portgrouped': {
		'id': 'emerging-botcc.portgrouped',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-botcc.portgrouped.rules',
		'file': 'emerging-botcc.portgrouped.rules',	
	},
	'Emerging threats ciarmy': {
		'id': 'emerging-ciarmy',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules',
		'file': 'emerging-ciarmy.rules',	
	},
	'Emerging threats compromised-BLOCK': {
		'id': 'emerging-compromised-BLOCK.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-compromised-BLOCK.rules',
		'file': 'emerging-compromised-BLOCK.rules',	
	},
	'Emerging threats compromised': {
		'id': 'emerging-compromised.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-compromised.rules',
		'file': 'emerging-compromised.rules',	
	},
	'Emerging threats drop': {
		'id': 'emerging-drop.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-drop.rules',
		'file': 'emerging-drop.rules',	
	},
	'Emerging threats dshield': {
		'id': 'emerging-dshield.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-dshield.rules',
		'file': 'emerging-dshield.rules',	
	},
	'Emerging threats rbn malvertising': {
		'id': 'emerging-rbn-malvertisers.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-rbn-malvertisers.rules',
		'file': 'emerging-rbn-malvertisers.rules',	
	},
	'Emerging threats rbn': {
		'id': 'emerging-rbn.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-rbn.rules',
		'file': 'emerging-rbn.rules',	
	},					
	'Emerging threats tor': {
		'id': 'emerging-tor.rules',
		'regex': '',
		'url':  'https://rules.emergingthreats.net/blockrules/emerging-tor.rules',
		'file': 'emerging-tor.rules',	
	}					
}

def downloadAndProcessBlocklist(url, regex, filename):
	req = urllib2.Request(url)
	req.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)')
	contents = ''
	
	#download blocklist
	try:
		response = urllib2.urlopen(req)
		contents = response.read()
										
	except urllib2.URLError as e:
		if hasattr(e, 'reason'):
			print 'We failed to reach a server.'
			print 'Reason: ', e.reason
		elif hasattr(e, 'code'):
			print 'The server couldn\'t fulfill the request.'
			print 'Error code: ', e.code
		else:
			print 'unknown error'

	#write to file
	try:
		with open(location+filename, 'w') as f:
			f.write(str(contents))
			f.close()
	except IOError as e:
	  	print e.reason


# main

#sensible defaults
location = '/usr/local/etc/snort/rules'

parser = argparse.ArgumentParser(description='IP blocklist downloader and importer for pf and ip tables')
parser.add_argument('-l', '--blocklist_location',help='location to store blocklists', required=False)
parser.add_argument('-n', '--blocklist_names',help='specify names of blocklists to download', required=False, type=lambda s: [str(item) for item in s.split(',')])

args = parser.parse_args()

if args.blocklist_location != None:
	location = args.blocklist_location


for key, value in sorted(blocklists.items()):

	#download all blocklists of the given type
	if args.blocklist_names == None:
		print('downloading '+key)
		downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])
	else:
		#download specified blocklists
		if value['id'] in args.blocklist_names:
			print('downloading '+key)
			downloadAndProcessBlocklist(value['url'], value['regex'], value['file'])
