#!/usr/bin/python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Nessus XML output parsing functions / utilities

Currently, only runs an XSLT transform to generate an HTML patch status
report - more stuff to come, though!

Ideas:
    Merge multiple nessus files
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
    args = parser.parse_args()
    
    target = args.nessus_input
    outdir = args.outdir
    is_merge = args.merge_files
    
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
        if is_merge:
            merge_nessus_files(infile_list,outdir)
            infile_list.append(os.path.join(outdir,"combined_report.nessus"))
                
    
    for infile in infile_list:
        for transform in transforms:
            outfile_base = transform[0]
            outfile_base += os.path.splitext(os.path.basename(infile))[0]
            outfile_base = os.path.join(outdir,outfile_base)
            transform_to_html(infile,outfile_base+'.html',transform[1])
            
    print "\n\nComplete!"
    print "Output data located at " + outdir

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
                    print "adding host: " + host.attrib['name']
                    report.append(host)
                else:
                    for item in host.findall('ReportItem'):
                        if not existing_host.find("ReportItem[@port='"+ item.attrib['port'] +"'][@pluginID='"+ item.attrib['pluginID'] +"']"):
                            print "adding finding: " + item.attrib['port'] + ":" + item.attrib['pluginID']
                            existing_host.append(item)
          print(":: => done.")    
       
    mainTree.write(os.path.join(outdir,"combined_report.nessus"), encoding="utf-8", xml_declaration=True)

if __name__ == '__main__':
    main()