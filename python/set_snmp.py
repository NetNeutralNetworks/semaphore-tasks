import yaml
import argparse
import os
import sys
import re
from time import sleep
from nc_mis.helpers.netbox import Netbox
from nc_mis.helpers.librenms import LibreNMS

import ipaddress

from nc_mis.drivers.hp.procurve import PROCURVE
from nc_mis.drivers.aruba.aos.AOS import AOS
from nc_mis.drivers.fs.fs import FS

import concurrent.futures
import multiprocessing
import logging

logger = logging.getLogger('nc-mis')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

MAX_WORKERS = 1#os.environ.get('MAX_WORKERS',multiprocessing.cpu_count()*4)
logger.info(f"Using {MAX_WORKERS} workers")

def C_RED(text): return f"\33[31m{text}\33[0m"
def C_GREEN(text): return f"\33[32m{text}\33[0m"
def C_YELLOW(text): return f"\33[33m{text}\33[0m"
def C_BOLD(text): return f"\33[1m{text}\33[0m"

def exec_pool(FUNCTION,LIST):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = executor.map(FUNCTION,LIST)
    return results 

def connect(DRIVER, device_ip, log_prefix='unknown'):
    try:
        device = DRIVER(ip=device_ip,
                            username=os.environ.get('device_username',''),
                            password=os.environ.get('device_password','')
                            )
        return device
    except:
        logger.info(C_RED(f"{log_prefix}: Management ip not found or failed to authenticate"))
        return    

def puch_change(lnms_device):
    config_changed = False
    try:
        device_os = lnms_device.get('os')
        device_ip = f"{os.environ.get('V6_PREFIX','')}{lnms_device.get('ip')}"
        device_name = lnms_device.get('sysName')

        snmp_config = nb_snmp_config
        
        log_prefix = f"{device_name}, {device_ip}, {device_os}"
        
        # prep commands
        commands = []
        
        if device_os == 'procurve':        
            device = connect(PROCURVE, device_ip, log_prefix)
            if not device: return { 'status': 'FAILED', 'device': log_prefix }
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            #conifgure communities
            communities = [i.get('community') for i in snmp_config.get('v2c',{})]
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for line in device_config.split('\n') if re.match('^snmp-server community .*', line) != None ]
                # drop removals that are planned for deployment                
                commands += [line for community in communities for line in remove_lines if community not in line]
            
            commands += [f"snmp-server community {s}"for s in communities]
            
            # configure traps
            trap_hosts = [i.get('trap_hosts') for i in snmp_config.get('v2c',{}) if i.get('trap_hosts')]
            if os.environ.get('replace',False):
                # find all config lines that match "snmp-server host <ip> community ..."
                regex = re.compile('^snmp-server host \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} community \S*')           
                remove_lines = [f"no {regex.match(line).group(0)}" for line in device_config.split('\n') if regex.match(line) != None ]
                # drop removals that are planned for deployment                
                commands += [l for l in remove_lines if l not in [line for trap_host in trap_hosts for line in remove_lines if f"snmp-server host {trap_host.get('ip','')} community \"{trap_host.get('community','')}\"" in line]]
            
            commands += [f"snmp-server host {trap_host.get('ip','')} community \"{trap_host.get('community','')}\"" for trap_host in trap_hosts]
            
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            # configure snmp v3
            #snmpv3 enable
            #snmpv3 user nc-snmp plaintext auth sha lkl priv aes kjkj
            
            if commands:
                # send commands to device
                device.conn.config_mode()
                for command in commands:
                    device.conn.send_command(command)
                device.conn.exit_config_mode()
                
                config_changed = True
            
        elif device_os == 'arubaos-cx' and False:        
            device = connect(AOS, device_ip, log_prefix)
            if not device: return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if re.match('^logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) != None ]
                # drop removals that are planned for deployment
                commands += [line for server in logservers for line in remove_lines if server not in line]
            
            commands += [f"logging {s}"for s in logservers]
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if commands:
                # send commands to device
                device.conn.config_mode()
                for command in commands:
                    device.conn.send_command(command)
                device.conn.exit_config_mode()
                
                config_changed = True
            
        elif device_os == 'fs-switch' and False:            
            device = connect(FS, device_ip, log_prefix)
            if not device: return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt()
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if re.match('^logging server \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) != None ]
                # drop removals that are planned for deployment
                commands += [line for server in logservers for line in remove_lines if server not in line]
            
            commands += [f"logging server {s}" for s in logservers]
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if commands:           
                # send commands to device
                device.conn.config_mode()
                for command in commands:
                    device.conn.send_command(command)
                device.conn.exit_config_mode()
                
                config_changed = True
            
        else:
            if os.environ.get('DEBUG',False):
                logger.info(f"{log_prefix}: No manufacturer set or device is not a switch")
            return { 'status': 'IGNORED', 'device': log_prefix }
        
    except Exception as e:
        logger.info (C_RED(f"{e}\n\n{log_prefix}: General failure, please contact an engineer to look into the issue, in the mean time check if changes can be done by logging in localy."))
        return { 'status': 'FAILED', 'device': log_prefix }
    
    # finish up
    device.conn.disconnect()
    if config_changed:
        device.write_config()
        logger.info(C_YELLOW(f"{log_prefix}: Config changed and saved"))
        return { 'status': 'CHANGED', 'device': log_prefix }
    else:
        logger.info(C_GREEN(f"{log_prefix}: No changes needed"))
        return { 'status': 'UNCHANGED', 'device': log_prefix }

librenms = LibreNMS()
netbox = Netbox()

lnms_devices = librenms.get_all_devices()
# filter only devices that are up 
lnms_devices = [d for d in lnms_devices if d.get('status') == 1]
lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
#nb_devices = netbox.get_all_devices()
nb_snmp_config = netbox._get_single("/api/extras/config-contexts/?name=snmp").get('results',[{}])[0].get('data',{}).get('snmp',[])

############################
# push changes
############################
results = list(exec_pool(puch_change,lnms_devices))

sorted_results = sorted(results, key=lambda d: d['status'])
logger.info('\n'+'\n'.join([str(r) for r in sorted_results]))


# to update librenms run the folling in the database cli:
# UPDATE devices set community='<community>' where os = '<os>';
#

    
    
    
    