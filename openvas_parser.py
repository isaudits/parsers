#!/usr/bin/python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

OpenVAS XML output parsing functions / utilities

Ideas:
    Generate host lists, port lists, etc to text and HTML

See README.md for licensing information and credits

'''
import argparse
import os

try:
    from lxml import etree
except:
    print "lxml module not installed try: "
    print "pip install lxml"
    print "     ----- OR -----"
    print "apt-get install python-lxml"
    

def main():
   
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "OpenVAS parsing automation script"
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('openvas_input', action='store', nargs='?',
                        help='Single XML or directory containing OpenVAS XML files to process \n \
                                (defaults to working directory if none specified)'
    )
    parser.add_argument('-o', '--outdir', action='store',
                        help='Output directory (default to specified target directory)'
    )
    
    parser.add_argument('-p', '--parse',
                        help='Parse openvas output files',
                        action='store_true'
    )
    args = parser.parse_args()
    
    target = args.openvas_input
    outdir = args.outdir
    is_parse = args.parse
    
    #------------------------------------------------------------------------------
    # Main stuff
    #------------------------------------------------------------------------------
    
    if not target:
        target = os.getcwd()
        print 'no  input file or directory specified - using working directory:'
        print target
        print ''
        
    
    # No output directory specified - use same directory as input target file/dir
    if not outdir:
        if os.path.isfile(target):
            outdir = os.path.dirname(target)
        else:
            outdir = target
        print 'no output directory specified - using ' + outdir
        print ''
    
    infile_list = []
    
    if os.path.isfile(target):
        infile_list.append(target)
    else:
        for infile in os.listdir(target):
            if os.path.isfile(os.path.join(target,infile)) and infile[-6:] == "nessus":
                infile_list.append(os.path.join(target,infile))

    
    #This currently doesnt really do anything - for debug purposes only            
    if is_parse:
        for infile in infile_list:
            parse_xml(infile)
        
    print "\n\nComplete!"

def parse_xml(filename_xml):
    parser = OpenvasParser(filename_xml)

def transform_to_html(infile, outfile, xsl):
    '''
    accepts an OpenVAS xml file and transform and exports to html
    NOTE - copied from Nessus parser and currently not being used
    '''
    
    output = ''
    dom = etree.parse(infile)
    
    try:
        xslt = etree.parse(xsl)
        transform = etree.XSLT(xslt)
        output = etree.tostring(transform(dom), pretty_print=True)
        
        output_file(outfile,output)
        
    except:
        print ''
        print '[!] Error parsing XSL for file '
        print ' -  make sure that the XSL transform is present and valid:'
        print ' -  ' + xsl

def output_file(outfile, output, overwrite=True):
    if overwrite == True:
        f = open(outfile, 'w+')
    else:
        f = open(outfile, 'w')
    
    f.write(output)
    f.close

def chop_port(portstring):
	# cut the portsection into service/port/protocol
	# converts from a string like "ssh (22/tcp)" into list
	# there is a difference in format between newer and older versions
	# of openvas, so the various sighted cases are covered here

	# Store port info in a dict with keys of service, protocol, port
	portinfo={}

	# cases where port looks like "general/icmp"
	if portstring.startswith("general/"):
		portstringlist = portstring.split("/")
		portinfo['service'] = portstringlist[0]
		portinfo['protocol'] = portstringlist[1]
		portinfo['port'] = "N/A"
		
	# cases where port looks like "ntp(123/udp)" 
	elif "(" in portstring:	
		# replace: ")" with "", the middle "(" with a /, then split the whole thing on /
		portstringlist = portstring.replace(")","").replace(" (","/").split("/")
		portinfo['service'] = portstringlist[0]
		portinfo['protocol'] = portstringlist[2]
		portinfo['port'] = portstringlist[1]
		
	# otherwise: port looks like "123/udp"
	else:
		portstringlist = portstring.split("/")
		portinfo['service'] = "" # empty for now so will leave it blank
		portinfo['protocol'] = portstringlist[1]
		portinfo['port'] = portstringlist[0]
	
	return portinfo

class OpenvasReport(object):
    def __init__(self):
        self.name=''
        self.hosts=[]

class OpenvasReportHost(object):
    def __init__(self):
        self.name=''
        self.host_ip=''
        self.scan_start=''
        self.scan_end=''
        self.hostname=''
        self.os=''
        self.cpe=''
        self.report_items=[]
        
class OpenvasReportItem(object):
    def __init__(self):
        
        self.name=''
        self.asset_id = ''
        self.port=''
        self.protocol=''
        self.svc_name=''
        
        #root level values
        self.comment=''
        self.scan_nvt_version=''
        self.threat=''
        self.severity=0.0
        self.description=''
        self.original_threat=''
        self.original_severity=''
        self.notes=''
        self.overrides=''
        
        #nvt
        self.oid=''
        self.type=''
        self.family=''
        self.cvss_base=0.0
        self.cve=[]
        self.bid=[]
        self.xref=[]
        
        #tags
        self.cvss_base_vector=''
        self.summary=''
        self.vuldetect=''
        self.insight=''
        self.impact=''
        self.solution=''
        self.solution_type=''
        self.qod_type=''
        
class OpenvasParser(object):
    def __init__(self, filename_xml):
        self.reports=[]
        if filename_xml == None or filename_xml == "":
            print "[!] No filename specified!"
            exit(1)
 
        # Parse input values in order to find valid .xml files
        self._xml_source = []
        if os.path.isdir(filename_xml):
            if not filename_xml.endswith("/"):
                filename_xml += "/"
            # Automatic searching of files into specified directory
            for path, dirs, files in os.walk(filename_xml):
                for f in files:
                    if f.endswith(".xml"):
                        self._xml_source.append(filename_xml + f)
                break
        elif filename_xml.endswith(".xml"):
            if not os.path.exists(filename_xml):
                print "[!] File specified '%s' not exist!" % filename_xml
                exit(3)
            self._xml_source.append(filename_xml)

        if not self._xml_source:
            print "[!] No file .xml to parse was found!"
            exit(3)
        
        # For each .nessus file found...
        for report in self._xml_source:
            # Parse and extract information
            self._parse_results(report)

    def _parse_results(self, file_report):
        
        tree = etree.parse(file_report)
        
        for report in tree.findall('./report'):
        
            openvas_report = OpenvasReport()
            
            # For each host in report file, it extracts information
            for host in report.findall('./host'):
                openvas_report_host = OpenvasReportHost()
                
                openvas_report_host.id = host.find('./asset').attrib['asset_id']
                
                if openvas_report_host.id:
                    openvas_report_host.name = host.find('ip').text
                    openvas_report_host.host_ip = openvas_report_host.name
                    openvas_report_host.scan_start = host.find('start').text
                    openvas_report_host.scan_end = host.find('end').text
                    hostprops = host.findall("detail")
                    
                    for prop in hostprops:
                        name = prop.find('name').text
                        value = prop.find('value').text
                        
                        if name == 'best_os_txt':
                            openvas_report_host.os = value
                            
                        if name == 'hostname':
                            openvas_report_host.hostname = value
                            
                        if name == 'best_os_cpe':
                            openvas_report_host.cpe = value
                                
                    # Add information extracted to data structure
                    openvas_report.hosts.append(openvas_report_host)
                    
            for result in report.findall('./results/result'):
                openvas_report_item = OpenvasReportItem()
                openvas_report_item.name = result.find('./name').text
                openvas_report_item.asset_id = result.find('./host/asset').attrib['asset_id']
                portinfo = chop_port(result.find('./port').text)
                openvas_report_item.port = portinfo['port']
                openvas_report_item.protocol = portinfo['protocol']
                openvas_report_item.svc_name = portinfo['service']
                
                items=['comment','scan_nvt_version','threat','severity','description','original_threat','original_severity','notes','overrides']
                for item in items:
                    node = result.find(item)
                    if node is not None:
                        setattr(openvas_report_item,item,node.text)
                
                
                openvas_report_item.oid = result.find('nvt').attrib['oid']
                items=['type','family','cvss_base']
                for item in items:
                    node = result.find('.nvt/'+item)
                    if node is not None:
                        setattr(openvas_report_item,item,node.text)
                    
                items=['cve','bid','xref']
                for item in items:
                    node = result.find('.nvt/'+item)
                    if node is not None:
                        setattr(openvas_report_item,item,node.text.split(','))
                
                #Parse info from tags element text
                tags = result.find('./nvt/tags').text
                if tags is not None:
                    tags = dict((k.strip(), v.strip()) for k,v in (item.split('=',1) for item in tags.split("|")))
                    items = ['summary', 'insight', 'impact', 'affected', 'solution', 'cvss_base_vector', 'qod_type', 'solution_type', 'vuldetect']
                    for item in items:
                        if item in tags:
                            setattr(openvas_report_item,item,tags[item])
                
                #Do a little cleanup on some of the values
                openvas_report_item.xref = [text.replace('URL:','') for text in openvas_report_item.xref]
                openvas_report_item.xref = [text.replace(' ','') for text in openvas_report_item.xref]
                if openvas_report_item.bid[0] == 'NOBID':
                    openvas_report_item.bid = []
                
                #Find appropriate host and append report finding as report_item
                for host in openvas_report.hosts:
                    if host.id == openvas_report_item.asset_id:
                        host.report_items.append(openvas_report_item)
                    
        self.reports.append(openvas_report)


if __name__ == '__main__':
    main()