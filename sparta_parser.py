#!/usr/bin/env python3
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

SecForce SPARTA database parsing functions / utilities

See README.md for licensing information and credits

'''
import argparse
import os
import sqlite3
        
class SpartaHost(object):
    def __init__(self):
        self.status=''      #up or down
        self.addr_ipv4=''
        self.addr_ipv6=''
        self.addr_mac=''
        self.addr_mac_vendor=''
        self.hostnames=[]
        self.os_name=''
        self.os_accuracy=0
        self.os_type=''     #NOT USED - mirroring nmap_parser script; Sparta keeps OS data from all runs in separate os data table
        self.os_family=''   #NOT USED - mirroring nmap_parser script
        self.os_vendor=''   #NOT USED - mirroring nmap_parser script
        self.os_gen=''      #NOT USED - mirroring nmap_parser script
        self.checked=False
        self.ports=[]
        self.host_scripts=[]
        self.host_actions=[]
        
class SpartaPort(object):
    def __init__(self):
        self.protocol=''    #tcp, udp
        self.port=0      #port number
        self.state=''       #open, closed, etc
        self.svc_name=''
        self.svc_product=''
        self.svc_version=''
        self.svc_extrainfo=''
        self.svc_conf=0         #NOT USED - mirroring nmap_parse script; Sparta doesnt track this
        self.port_scripts=[]
        self.port_actions=[]
        
class SpartaNmapScript(object):
    '''
    Stores results from nmap scripts from both host scripts and port scripts
    
    Host actions will be parsed as sub-objects of a host
    Port actions will be parsed as sub-objects of a port/service
    '''
    def __init__(self):
        self.script_id=''
        self.script_output=''
        
class SpartaAction(object):
    '''
    Stores results from both host actions (e.g. traceroute) and port actions (e.g. Nikto scan)
    
    Host actions will be parsed as sub-objects of a host
    Port actions will be parsed as sub-objects of a port/service
    
    Nmap scripts are excluded since they are stored in a different database table
    Screenshots and tools which do not have any output stored in the Sparta database table
    are also excluded since they are stored only as flat files and we currently have not
    identified an effective way to get that information...SORRY!
    '''
    def __init__(self):
        self.tool_name=''
        self.tool_command=''
        self.tool_output=''
        self.tool_starttime=''
        self.tool_endtime=''
        
class SpartaParser(object):
    '''
    Accepts a SPARTA .sprt database file location and parses into objects usable in Python
    Top level is a list of hosts with sub-objects containing ports/services and nmap script
    results (designed to mirror our NmapParser class for consistency) as well as tool output
    also linked to a particular port/host
    
    NOTE - do not anticipate processing a directory full of these things so currently not
    accepting directory names and passing to an array like we do with other parsers.
    Top level result of the parser will be a list of host objects
    '''
    def __init__(self, file_path):
        self.hosts=[]
        
        #Use expanduser just in case the path includes user environment variable
        self.connection=sqlite3.connect(os.path.expanduser(file_path))
        self.cursor=self.connection.cursor()
        
        if self._validate_file(file_path) == True:
            self._parse_results(file_path)
            
    def _validate_file(self, file_path):
        #TODO - implement this; now we process anything!
        return True
    
    def _parse_results(self, file_path):
        '''
        TODO - MODIFY QUERIES TO BRING IN SPARTA ID KEYS AND USE THOSE TO QUERY FOREIGN KEYS
        '''
        
        qry_hosts = """SELECT id, checked, os_match, os_accuracy, ip, ipv4, ipv6, macaddr, status, hostname, vendor,
                            uptime, lastboot, distance, state, count
                        FROM db_tables_nmap_host
                    """
        self.cursor.execute(qry_hosts)
        hosts = self.cursor.fetchall()
        for host in hosts:
            (host_id, host_checked, host_os_match, host_os_accuracy, host_ip, host_ipv4, host_ipv6, host_macaddr,
             host_status, host_hostname, host_vendor, host_uptime, host_lastboot, host_distance, host_state, host_count) = host
            
            sparta_host=SpartaHost()
            sparta_host.status=host_status
            sparta_host.addr_ipv4=host_ipv4
            sparta_host.addr_ipv6=host_ipv6
            sparta_host.addr_mac=host_macaddr
            sparta_host.addr_mac_vendor=host_vendor
            sparta_host.hostnames.append(host_hostname)
            sparta_host.os_name=host_os_match
            sparta_host.os_accuracy=host_os_accuracy
            sparta_host.checked=host_checked
            
            qry_hostscripts="""SELECT db_tables_nmap_script.script_id, db_tables_nmap_script.output 
                                FROM db_tables_nmap_script
                                INNER JOIN db_tables_nmap_host ON db_tables_nmap_host.id = db_tables_nmap_script.host_id
                                WHERE (port_id IS NULL OR port_id = '') AND db_tables_nmap_host.id = '%s'""" % host_id
                                
            self.cursor.execute(qry_hostscripts)
            hostscripts = self.cursor.fetchall()
            for hostscript in hostscripts:
                (script_id, script_output) = hostscript
                sparta_hostscript=SpartaNmapScript()
                sparta_hostscript.script_id=script_id
                sparta_hostscript.script_output=script_output
                sparta_host.host_scripts.append(sparta_hostscript)
            
            qry_hostactions="""SELECT name, command, output, starttime, endtime
                                FROM db_tables_process
                                INNER JOIN db_tables_process_output on db_tables_process.id = db_tables_process_output.process_id
                                WHERE db_tables_process.name <> 'nmap' AND db_tables_process.pid > 0 AND db_tables_process.status='Finished'
                                    AND (port IS NULL OR port = '') AND hostip = '%s'""" % host_ipv4
            
            self.cursor.execute(qry_hostactions)
            hostactions = self.cursor.fetchall()
            for hostaction in hostactions:
                (action_name, action_command, action_output, action_starttime, action_endtime) = hostaction
                sparta_hostaction=SpartaAction()
                sparta_hostaction.tool_name=action_name
                sparta_hostaction.tool_command=action_command
                sparta_hostaction.tool_output=action_output
                sparta_hostaction.tool_starttime=action_starttime
                sparta_hostaction.tool_endtime=action_endtime
                sparta_host.host_actions.append(sparta_hostaction)
            
            qry_ports = """SELECT db_tables_nmap_port.id, db_tables_nmap_host.ip, db_tables_nmap_port.port_id,
                                db_tables_nmap_port.protocol, db_tables_nmap_port.state, db_tables_nmap_service.name,
                                db_tables_nmap_service.product, db_tables_nmap_service.version, db_tables_nmap_service.extrainfo
                            FROM db_tables_nmap_host
                            INNER JOIN db_tables_nmap_port ON db_tables_nmap_host.id = db_tables_nmap_port.host_id
                            INNER JOIN db_tables_nmap_service ON db_tables_nmap_port.service_id = db_tables_nmap_service.id
                            WHERE db_tables_nmap_host.id = '%s'""" % host_id
            
            self.cursor.execute(qry_ports)
            ports = self.cursor.fetchall()
            for port in ports:
                (port_id, host_ip, port_port, port_protocol, port_state, port_service_name, port_service_product, port_service_version,
                 port_service_extrainfo) = port
                
                sparta_port=SpartaPort()
                sparta_port.port_id=port_id
                sparta_port.port=port_port
                sparta_port.protocol=port_protocol
                sparta_port.state=port_state
                sparta_port.svc_name=port_service_name
                sparta_port.svc_product=port_service_product
                sparta_port.svc_version=port_service_version
                sparta_port.svc_extrainfo=port_service_extrainfo
                
                qry_portscripts="""SELECT db_tables_nmap_script.script_id, db_tables_nmap_script.output 
                                    FROM db_tables_nmap_script
                                    INNER JOIN db_tables_nmap_port ON db_tables_nmap_port.id = db_tables_nmap_script.port_id
                                    WHERE db_tables_nmap_port.id = '%s'""" % port_id
                
                self.cursor.execute(qry_portscripts)
                portscripts = self.cursor.fetchall()
                for portscript in portscripts:
                    (script_id, script_output) = portscript
                    sparta_portscript=SpartaNmapScript()
                    sparta_portscript.script_id=script_id
                    sparta_portscript.script_output=script_output
                    sparta_port.port_scripts.append(sparta_portscript)
                
                qry_portactions="""SELECT name, command, output, starttime, endtime
                                    FROM db_tables_process
                                    INNER JOIN db_tables_process_output on db_tables_process.id = db_tables_process_output.process_id
                                    WHERE db_tables_process.name <> 'nmap' AND db_tables_process.pid > 0 AND db_tables_process.status='Finished'
                                        AND hostip = '%s' AND port = '%s' AND protocol = '%s'""" % (host_ipv4, port_port, port_protocol)
                
                self.cursor.execute(qry_portactions)
                portactions = self.cursor.fetchall()
                for portaction in portactions:
                    (action_name, action_command, action_output, action_starttime, action_endtime) = portaction
                    sparta_portaction=SpartaAction()
                    sparta_portaction.tool_name=action_name
                    sparta_portaction.tool_command=action_command
                    sparta_portaction.tool_output=action_output
                    sparta_portaction.tool_starttime=action_starttime
                    sparta_portaction.tool_endtime=action_endtime
                    sparta_port.port_actions.append(sparta_portaction)
                    
                sparta_host.ports.append(sparta_port)
    
            self.hosts.append(sparta_host)
    
def main():
   
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Sparta parsing automation script"
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('infile', action='store', nargs='?',
                        help='Sparta file to parse'
    )
    
    args = parser.parse_args()
    
    infile = os.path.expanduser(args.infile)

    #------------------------------------------------------------------------------
    # Main stuff
    #------------------------------------------------------------------------------
    
    parser = SpartaParser(infile)



if __name__ == '__main__':
    main()