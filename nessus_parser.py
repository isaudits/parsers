#!/usr/bin/env python3
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Nessus XML output parsing functions / utilities

Ideas:
    Generate host lists, port lists, etc to text and HTML

Credit Allesandro Di Pinto (YANP) for borrowed code for parsing class functions
(https://github.com/adipinto/yet-another-nessus-parser)

See README.md for licensing information and credits

'''
import argparse
import os
import re

try:
    from lxml import etree
except:
    print("lxml module not installed try: ")
    print("pip install lxml")
    print("     ----- OR -----")
    print("apt-get install python-lxml")
    

def main():
   
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Nessus parsing automation script"
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('nessus_input', action='store', nargs='?',
                        help='Single XML or directory containing Nessus XML files to process \n \
                                (defaults to working directory if none specified)'
    )
    parser.add_argument('-o', '--outdir', action='store',
                        help='Output directory (default to specified target directory)'
    )
    parser.add_argument('-m', '--merge_files',
                        help='Merge multiple input files into a single .nessus out file before processing',
                        action='store_true'
    )
    parser.add_argument('-t', '--transform',
                        help='Run XSLT transforms on specified .xml files',
                        action='store_true'
    )
    parser.add_argument('-p', '--parse',
                        help='Parse nessus output files',
                        action='store_true'
    )
    args = parser.parse_args()
    
    target = args.nessus_input
    outdir = args.outdir
    is_merge = args.merge_files
    is_transform = args.transform
    is_parse = args.parse

    
    #------------------------------------------------------------------------------
    # Set up array of transforms to run
    #
    # [0] - name, which will be prepended to output file
    # [1] - location of transform file to apply
    #------------------------------------------------------------------------------
    transforms = []
    transforms.append(["patch_report", "./transforms/nessus_patch_status.xslt"])
    transforms.append(["compliance_report", "./transforms/nessus_compliance_report.xslt"])
    transforms.append(["metasploit_report", "./transforms/nessus_metasploit_available.xslt"])
    
    #------------------------------------------------------------------------------
    # Main stuff
    #------------------------------------------------------------------------------
    
    if not target:
        target = os.getcwd()
        print('no  input file or directory specified - using working directory:')
        print(target)
        print('')
        
    
    # No output directory specified - use same directory as input target file/dir
    if not outdir:
        if os.path.isfile(target):
            outdir = os.path.dirname(target)
        else:
            outdir = target
        print('no output directory specified - using ' + outdir)
        print('')
    
    infile_list = []
    
    if os.path.isfile(target):
        infile_list.append(target)
    else:
        for infile in os.listdir(target):
            if os.path.isfile(os.path.join(target,infile)) and infile[-6:] == "nessus":
                infile_list.append(os.path.join(target,infile))
        
    if is_merge:
        merge_nessus_files(infile_list,outdir)
        infile_list.append(os.path.join(outdir,"combined_report.nessus"))
    
    if is_transform:        
        for infile in infile_list:
            for transform in transforms:
                outfile_base = transform[0]
                outfile_base += os.path.splitext(os.path.basename(infile))[0]
                outfile_base = os.path.join(outdir,outfile_base)
                transform_to_html(infile,outfile_base+'.html',transform[1])
    
    #This currently doesnt really do anything - for debug purposes only            
    if is_parse:
        for infile in infile_list:
            parse_xml(infile)
        
    print("\n\nComplete!")
    print("Output data located at " + outdir)

def parse_xml(filename_xml):
    parser = NessusParser(filename_xml)

def transform_to_html(infile, outfile, xsl):
    '''
    accepts a nessus xml file and transform and exports to html
    '''
    
    output = ''
    dom = etree.parse(infile)
    
    try:
        xslt = etree.parse(xsl)
        transform = etree.XSLT(xslt)
        output = etree.tostring(transform(dom), pretty_print=True)
        
        output_file(outfile,output)
        
    except:
        print('')
        print('[!] Error parsing XSL for file ')
        print(' -  make sure that the XSL transform is present and valid:')
        print(' -  ' + xsl)

def output_file(outfile, output, overwrite=True):
    if overwrite == True:
        f = open(outfile, 'w+')
    else:
        f = open(outfile, 'w')
    
    f.write(output)
    f.close

def merge_nessus_files(infile_list, outdir):
    # logic borrowed from https://gist.github.com/mastahyeti/2720173

    first = 1
    for infile in infile_list:
          if first:
             mainTree = etree.parse(infile)
             report = mainTree.find('Report')
             report.attrib['name'] = 'Merged Report'
             first = 0
          else:
             tree = etree.parse(infile)
             for host in tree.findall('.//ReportHost'):
                existing_host = report.find(".//ReportHost[@name='"+host.attrib['name']+"']")
                if not existing_host:
                    print("adding host: " + host.attrib['name'])
                    report.append(host)
                else:
                    for item in host.findall('ReportItem'):
                        if not existing_host.find("ReportItem[@port='"+ item.attrib['port'] +"'][@pluginID='"+ item.attrib['pluginID'] +"']"):
                            print("adding finding: " + item.attrib['port'] + ":" + item.attrib['pluginID'])
                            existing_host.append(item)
          print(":: => done.")    
       
    mainTree.write(os.path.join(outdir,"combined_report.nessus"), encoding="utf-8", xml_declaration=True)

class NessusReport(object):
    def __init__(self):
        self.name=''
        self.hosts=[]

class NessusReportHost(object):
    def __init__(self):
        self.name=''
        self.host_ip=''
        self.scan_start=''
        self.scan_end=''
        self.host_fqdn=''
        self.netbios_name=''
        self.mac_address=''
        self.operating_system=''
        self.os=''
        self.report_items=[]
        
class NessusReportItem(object):
    def __init__(self):
        self.plugin_id=''
        self.plugin_name=''
        self.plugin_family=''
        self.port=''
        self.protocol=''
        self.svc_name=''
        self.severity=0
        
        self.agent=''
        self.bid=[]
        self.cert=''
        self.cpe=''
        self.cve=[]
        self.cvss_base_score=0.0
        self.cvss_vector=''
        self.cvss_temporal_score=0.0
        self.cvss_temporal_vector=''
        self.cvss3_base_score=0.0
        self.cvss3_vector=''
        self.cvss3_temporal_score=0.0
        self.cvss3_temporal_vector=''
        self.cvss_score_source=''
        self.description=''
        self.exploit_available=''
        self.exploit_code_maturity=''
        self.exploit_framework_canvas=''
        self.exploit_framework_core=''
        self.exploit_framework_metasploit=''
        self.exploitability_ease=''
        self.exploited_by_malware=''
        self.fname=''
        self.iava=[]
        self.msft=[]
        self.metasploit_name=''
        self.osvdb=[]
        self.patch_publication_date=''
        #SKIP plugin_name since defined in host attribute section above
        self.plugin_modification_date=''
        self.plugin_type=''
        self.risk_factor=''
        self.script_version=''
        self.see_also=''
        self.solution=''
        self.stig_severity=''
        self.synopsis=''
        self.vuln_publication_date=''
        self.xref=[]
        self.plugin_output=''
        
class NessusParser(object):
    def __init__(self, filename_xml='', xml=''):
        self.reports=[]
 
        if filename_xml:
            # Parse input values in order to find valid .nessus files
            self._xml_source = []
            if os.path.isdir(filename_xml):
                if not filename_xml.endswith("/"):
                    filename_xml += "/"
                # Automatic searching of files into specified directory
                for path, dirs, files in os.walk(filename_xml):
                    for f in files:
                        if f.endswith(".nessus"):
                            self._xml_source.append(filename_xml + f)
                    break
            elif filename_xml.endswith(".nessus"):
                if not os.path.exists(filename_xml):
                    print("[!] File specified '%s' not exist!" % filename_xml)
                    exit(3)
                self._xml_source.append(filename_xml)
    
            if not self._xml_source:
                print("[!] No file .nessus to parse was found!")
                exit(3)
            
            # For each .nessus file found...
            for report in self._xml_source:
                # Parse and extract information
                self._parse_results(report)
                
        elif xml:
            self._parse_results('', xml)
            
        else:
            print("[!] No xml data passed to parser!")
            exit(1)

    def _parse_results(self, file_report='', xml_report=''):
        
        if file_report:
            tree = etree.parse(file_report)
        elif xml_report:
            tree = etree.fromstring(xml_report)
        
        for report in tree.findall('Report'):
        
            nessus_report = NessusReport()
            nessus_report.name = report.get('name')
            
            # For each host in report file, it extracts information
            for host in report.findall('ReportHost'):
                nessus_report_host = NessusReportHost()
                # Get IP address
                nessus_report_host.name = host.get('name')
                if nessus_report_host.name:
                    hostprops = host.find("HostProperties").findall("tag")
                    
                    for prop in hostprops:
                        if prop.get('name') == 'host-ip':
                            nessus_report_host.host_ip = prop.text
                            
                        if prop.get('name') == 'HOST_START':
                            nessus_report_host.scan_start = prop.text
                            
                        if prop.get('name') == 'HOST_END':
                            nessus_report_host.scan_end = prop.text
                            
                        if prop.get('name') == 'operating-system':
                            nessus_report_host.operating_system = prop.text
                            
                        if prop.get('name') == 'os':
                            nessus_report_host.os = prop.text
                            
                        if prop.get('name') == 'host-fqdn':
                            nessus_report_host.host_fqdn = prop.text
                            
                        if prop.get('name') == 'netbios-name':
                            nessus_report_host.netbios_name = prop.text
                            
                        if prop.get('name') == 'mac-address':
                            nessus_report_host.mac_address = prop.text
                                
                    # Add information extracted to data structure
                    nessus_report.hosts.append(nessus_report_host)
                    
                    reportitems = host.findall("ReportItem")
                    for item in reportitems:
                        nessus_report_item = NessusReportItem()
                        # Extract generic vulnerability information
                        nessus_report_item.plugin_name = item.get('pluginName')
                        nessus_report_item.plugin_id = item.get('pluginID')
                        nessus_report_item.port = item.get('port')
                        nessus_report_item.protocol = item.get('protocol')
                        nessus_report_item.description = item.get('description')
                        nessus_report_item.svc_name = item.get('svc_name')
                        nessus_report_item.severity = int(item.get('severity'))

                        

                        # Report item child nodes to be extracted are enumerated in the following arrays;
                        # text_nodes contains all unique nodes
                        # array_nodes contains nodes in which multiple instances can be found; these are returned as a list
                        text_nodes=['agent','cert','cpe','cvss_base_score','cvss_vector','cvss_temporal_score','cvss_temporal_vector',
                                    'cvss3_base_score','cvss3_vector','cvss3_temporal_score','cvss3_temporal_vector', 'cvss_score_source',
                                    'description', 'exploit_available', 'exploit_code_maturity', 'exploit_framework_core', 'exploit_framework_canvas',
                                    'exploit_framework_metasploit','exploitability_ease', 'exploited_by_malware', 'metasploit_name', 
                                    'patch_publication_date','plugin_modification_date','plugin_type', 'risk_factor','script_version',
                                    'see_also','solution','stig_severity','synopsis','vuln_publication_date','plugin_output']
                        
                        array_nodes=['bid','cve','iava','msft','osvdb','xref']

                        for node in text_nodes:
                            if item.find(node) is not None:
                                node_value = item.find(node).text

                                # clean up CVSS vector data
                                if 'cvss' in node and 'vector' in node:
                                    node_value = node_value.replace('CVSS2#','')

                                setattr(nessus_report_item,node,node_value)
                                
                        for node in array_nodes:
                            if item.find(node) is not None:
                                array=[]
                                for hit in item.findall(node):
                                    array.append(hit.text)
                                setattr(nessus_report_item,node,array)
                        
                        #Cleanup some of the screwball formatting from Nessus
                        nessus_report_item.plugin_name = nessus_report_item.plugin_name.replace(")-", ") - ")
                        nessus_report_item.plugin_name = nessus_report_item.plugin_name.replace("s(", "s (")
                        nessus_report_item.plugin_name = nessus_report_item.plugin_name.replace("e(", "e (")
                        nessus_report_item.synopsis = nessus_report_item.synopsis.replace("\n  ", " ")
                        nessus_report_item.description = nessus_report_item.description.replace("\n  -", "\n•")
                        nessus_report_item.description = nessus_report_item.description.replace("\n -", "\n•")
                        nessus_report_item.description = nessus_report_item.description.replace("\n\n  ", "\n\n")
                        nessus_report_item.description = nessus_report_item.description.replace("\n\n ", "\n\n")
                        nessus_report_item.description = nessus_report_item.description.replace("     ", " ")
                        nessus_report_item.description = nessus_report_item.description.replace("\n    ", " ")
                        nessus_report_item.description = nessus_report_item.description.replace("\n   ", " ")
                        nessus_report_item.description = nessus_report_item.description.replace("\n  ", " ")
                        nessus_report_item.description = nessus_report_item.description.replace("\n ", " ")
                        nessus_report_item.solution = nessus_report_item.solution.replace("\n  -", "\n•")
                        nessus_report_item.solution = nessus_report_item.solution.replace("\n -", "\n•")
                        nessus_report_item.solution = nessus_report_item.solution.replace("\n  ", " ")
                        nessus_report_item.solution = nessus_report_item.solution.replace("\n ", " ")


                        nessus_report_host.report_items.append(nessus_report_item)

                        
        
        self.reports.append(nessus_report)


if __name__ == '__main__':
    main()