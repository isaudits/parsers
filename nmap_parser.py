#!/usr/bin/python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Nmap XML output parsing functions / utilities

Currently limited to exporting XML scan results to HTML and .TXT but
hopefully more cool stuff to come!!!

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
    desc = "Nmap parsing automation script; "
    desc += "currently only export capabilities but more advanced processing to come! "
    desc += "exports to both text and html if no output options (--text, --html) are specified."
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('nmap_input', action='store', nargs='?',
                        help='Single XML or directory containing Nmap XML files to process \n \
                                (defaults to working directory if none specified)'
    )
    parser.add_argument('-o', '--outdir', action='store',
                        help='Output directory (default to specified target directory)'
    )
    parser.add_argument('--text',
                        help='Output to text',
                        action='store_true'
    )
    parser.add_argument('--html',
                        help='Output to html',
                        action='store_true'
    )
    parser.add_argument('--xsl', action='store',
                        help='Nmap xml stylesheet (defaults to xml-stylesheet from nmap XML files)'
    )
    args = parser.parse_args()
    
    target = args.nmap_input
    outdir = args.outdir
    xsl = args.xsl
    is_text = args.text
    is_html = args.html
    
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
    
    # No output options specified - enable all!
    if not is_text and not is_html:
        is_text = True
        is_html = True
    
    print 'Text output enabled: ' + str(is_text)
    print 'HTML output enabled: ' + str(is_html)
    
    infile_list = []
    
    if os.path.isfile(target):
        infile_list.append(target)
    else:
        for infile in os.listdir(target):
            if os.path.isfile(os.path.join(target,infile)) and infile[-3:] == "xml":
                infile_list.append(os.path.join(target,infile))
    
    for infile in infile_list:
        outfile_base = os.path.join(outdir,os.path.splitext(os.path.basename(infile))[0])
        if is_text:
            nmap_out_to_txt(infile,outfile_base+'.txt')
        if is_html:
            nmap_out_to_html(infile,outfile_base+'.html',xsl)
            
    print "\n\nComplete!"
    print "Output data located at " + outdir

def nmap_out_to_html(infile, outfile, xsl=''):
    '''
    accepts an nmap xml file and exports to html
    '''
    
    output = ''
    dom = etree.parse(infile)
    
    try:
        if xsl:
            xslt = etree.parse(xsl)
        else:
            docroot = dom.getroot()
            pi = docroot.getprevious()
            if isinstance(pi,etree._XSLTProcessingInstruction):
                xsl = pi.attrib['href']
                xslt = pi.parseXSL()
        
        transform = etree.XSLT(xslt)
        output = etree.tostring(transform(dom), pretty_print=True)
        
        output_file(outfile,output)
        
    except:
        print ''
        print '[!] Error parsing XSL for file '
        print ' -  make sure that the XSL transform is present and valid:'
        print ' -  ' + xsl
    
def nmap_out_to_txt(infile, outfile):
    output = ''

    e = etree.parse(infile).getroot()
    
    for child in e.iter('output'):
        output += child.text
    
    output_file(outfile,output)
    
def output_file(outfile, output, overwrite=True):
    if overwrite == True:
        f = open(outfile, 'w+')
    else:
        f = open(outfile, 'w')
    
    f.write(output)
    f.close

    
if __name__ == '__main__':
    main()