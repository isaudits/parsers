#!/usr/bin/env python3

import argparse
import sys
import os
import shutil
import time
import re
import logging
from datetime import datetime
import email.policy
import email.parser
import email.utils

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:
    raise ImportError('jinja2 module not found; try pip install jinja2')

try:
    import dateutil.parser
except ImportError:
    raise ImportError('dateutil module not found; try pip install python-dateutil')


class MailItem:
    '''
    One of the following input types is required
    filepath: string to mail file of any type; get_file will read the file and process as .eml or .msg accordingly
    raw_message: string containing raw text of email file content (.eml format)
    msg_file
    '''
    def __init__(self, filepath='', raw_message='', msg_file=''):
        self.filepath=filepath
        self.raw_message=raw_message
        self.msg_file=msg_file
        self.message=None               #This will be parsed EmailMessage class
        self.message_id=''
        self.date=None
        self.mail_from=''
        self.mail_to=''
        self.mail_cc=''
        self.reply_to=''
        self.subject=''
        self.body=''
        self.body_html=''
        self.body_text=''
        self.raw_header=''
        #self.received=[]                #list of transport hops
        self.hops={}
        self.summary_headers={}
        self.security_headers={}
        self.other_headers={}
        self.outfile=''
        self.ref=''
        
        if self.filepath:
            self.get_file()
            
        if self.raw_message:
            self.parse_eml()
        elif self.msg_file:
            self.parse_msg()
            
    def get_file(self):
        if self.filepath.endswith('.eml'):
            with open(self.filepath, 'r') as mail_file:
                self.raw_message = mail_file.read()
            
        elif self.filepath.endswith('.msg'):
            self.msg_file=self.filepath
    
    def parse_msg(self):
        try:
            import extract_msg
        except ImportError:
            raise ImportError('extract_msg required to process .msg files; try pip install extract-msg')
        
        msg = extract_msg.Message(self.msg_file)
        
        self.message = msg.header           #extract_msg.header returns a python email.Message class
        self.raw_header = str(msg.header)
        self.body=msg.body
        self.body_text=msg.body
        self.body_html=msg.htmlBody
        
        self.parse_headers()
        

    def parse_eml(self):
        try:
            # use email.policy.default to get an EmailMessage instead of a Message class (exposes get_body())
            self.message = email.parser.Parser(policy=email.policy.default).parsestr(self.raw_message)
            self.raw_header = str(email.parser.HeaderParser(policy=email.policy.default).parsestr(self.raw_message))
            self.body = self.message.get_body()
            self.body_html = self.message.get_body(preferencelist=('html'))
            self.body_text = self.message.get_body(preferencelist=('plain'))
        except:
            print('Error parsing raw email - skipping...')
            return
        
        self.parse_headers()
        
    def parse_headers(self):
        
        
        received = self.message.get_all('Received')
        
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', str(self.message), re.X | re.DOTALL | re.I)
        
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
        
            org_time = line[-1]
        
            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)
        

            self.hops[c] = {
                'Timestamp': org_time,
                'From': data[0][0],
                'By': data[0][1],
                'With': data[0][2]
            }
            
            c -= 1
        
        self.date = email.utils.parsedate_to_datetime(self.message.get('Date'))
        
        summary_header_list = ['From', 'Reply-To', 'To', 'CC', 'Subject', 'Message-ID', 'Date']
        
        security_header_list = ['Received-SPF', 'received-spf', 'Authentication-Results', 'Authentication-Results-Original', 'X-Original-Authentication-Results'
                            'DKIM-Signature', 'ARC-Authentication-Results']
        
        for k,v in self.message.items():
            if k in summary_header_list:
                self.summary_headers[k]=v.replace('\n','')
            elif k in security_header_list:
                self.security_headers[k]=v.replace('\n','')
            elif k != 'Received':
                self.other_headers[k]=v.replace('\n','')
        
        for k,v in self.summary_headers.items():
            v=v.replace('"','')
            
            if k == 'From': self.mail_from = v
            elif k == 'To': self.mail_to = v
            elif k == 'CC': self.mail_cc = v
            elif k == 'Reply-To': self.reply_to = v
            elif k == 'Subject': self.subject = v
            elif k == 'Message-ID': self.message_id = v

    
def export_html(result, outfile='output.html', skip_sent=False, skip_duplicate=False):
    
    directory=os.path.dirname(outfile)
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    directory=os.path.join(os.path.dirname(outfile),"files")
    if not os.path.exists(directory):
        os.makedirs(directory)
        
    if skip_sent:
        directory=os.path.join(os.path.dirname(outfile),"skipped-sent")
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        skipped = [x for x in result if not x.hops]
        result = [x for x in result if x.hops]
        
        i=1
        for item in skipped:
            if item.filepath:
                filename=str(i)+"_"+item.subject[0:20]+"."+os.path.splitext(item.filepath)[1]
                filename = re.sub(r'[\\/*?:"<>|]',"",filename)
                
                shutil.copy(item.filepath, os.path.join(os.path.dirname(outfile),"skipped-sent",filename))
                item.outfile=os.path.join("skipped-sent",filename)
            i=i+1
    
    
    if skip_duplicate:
        directory=os.path.join(os.path.dirname(outfile),"skipped-duplicate")
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        ids=[]
        duplicates=[]
        result_temp=result
        result=[]
        i=1
        for item in result_temp:
            print("Checking "+item.message_id)
            if item.message_id in ids:
                print(item.message_id+" is duplicate")
                if item.filepath:
                    filename=str(i)+"_"+item.subject[0:20]+"."+os.path.splitext(item.filepath)[1]
                    filename = re.sub(r'[\\/*?:"<>|]',"",filename)
                    
                    shutil.copy(item.filepath, os.path.join(os.path.dirname(outfile),"skipped-duplicate",filename))
                    item.outfile=os.path.join("skipped-duplicate",filename)
                i=i+1
                
                duplicates.append(item)
                
            else:
                result.append(item)
                ids.append(item.message_id)
    
    i=1
    for item in result:
        item.ref=str(i)
        if item.filepath:
            filename=str(i)+"_"+item.subject[0:20]+"."+os.path.splitext(item.filepath)[1]
            filename = re.sub(r'[\\/*?:"<>|]',"",filename)
            
            shutil.copy(item.filepath, os.path.join(os.path.dirname(outfile),"files",filename))
            item.outfile=os.path.join("files",filename)
        i=i+1
    
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("email_parser.html") 
    output_data = template.render(data=result)
    
    f = open(outfile, 'w')
    f.write(output_data)
    f.close()
    
    

def main(argv):
    parser = argparse.ArgumentParser(description='Email parser and header analyzer')
    parser.add_argument('-d','-vv','--debug',
                        help='Print lots of debugging statements',
                        action="store_const",dest="loglevel",const=logging.DEBUG,
                        default=logging.WARNING
    )
    parser.add_argument('-v','--verbose',
                        help='Be verbose',
                        action="store_const",dest="loglevel",const=logging.INFO
    )
    parser.add_argument('filepath', action='store', help='Path to email file or folder containing files')
    parser.add_argument('-o','--outpath', action='store', dest='outpath', help='Output path')
    parser.add_argument('--skip-sent', help='Skip emails which were sent as opposed to received (no headers)',
                        action='store_true', dest='skip_sent'
    )
    parser.add_argument('--skip-duplicate', help='Skip emails with duplicate message-id headers',
                        action='store_true', dest='skip_duplicate'
    )
    args = parser.parse_args()
    
    filepath = args.filepath
    outpath = args.outpath
    skip_sent = args.skip_sent
    skip_duplicate = args.skip_duplicate
    file_list = []
    
    if os.path.isdir(filepath) == True:
        dirlist = os.listdir(filepath)
        for file in dirlist:
            if file.endswith('.eml') or file.endswith('.msg'):
                file_list.append(os.path.join(filepath,file))
                
        if not outpath:
            outpath = os.path.join(filepath, 'output')
    else:
        file_list.append(filepath)
        
        if not outpath:
            outpath = os.path.join(os.path.dirname(filepath), 'outpath')
    
    result = []
    
    for file in file_list:
        email = MailItem(filepath=file)
        
        # if email.message is blank then parsing was unsuccessful...
        if email.message:
            result.append(email)
            
    result.sort(key=lambda x: x.date, reverse=False)
    
    if outpath:
        outfile=os.path.join(outpath, 'output.html')
    else:
        outfile='output.html'
        
    export_html(result, outfile, skip_sent, skip_duplicate)
    
if __name__ == "__main__":
    main(sys.argv[1:])