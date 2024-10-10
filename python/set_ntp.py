import subprocess, sys
subprocess.run([sys.executable, "-m", "pip", "install", "-r", "python/requirements.txt"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

import yaml
import argparse
import os
import re
from time import sleep
from nc_helpers.netbox import Netbox
from nc_helpers.librenms import LibreNMS

import ipaddress

from nc_mis.drivers.hp.procurve import PROCURVE
from nc_mis.drivers.aruba.aos.AOS import AOS
from nc_mis.drivers.fs.fs import FS

import concurrent.futures
import multiprocessing
import logging

logger = logging.getLogger('nc-mis')
if os.environ.get('DEBUG',False):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)
    
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

MAX_WORKERS = int(os.environ.get('MAX_WORKERS',multiprocessing.cpu_count()*4))
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

def push_change(lnms_device):
    config_changed = False
    try:
        device_os = lnms_device.get('os')
        device_ip = f"{os.environ.get('V6_PREFIX','')}{lnms_device.get('ip')}"
        device_name = lnms_device.get('sysName')
        
        log_prefix = f"{device_name}, {device_ip}, {device_os}"
        
        ntpservers = nb_ntpservers.get('servers')
        
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
            output = device.conn.send_command("show ntp status")
            
            if "Invalid input: ntp" in output:
                return { 'status': 'SKIPPED', 'device': f"{log_prefix}: ntp not supported"}
            
            # disable sntp
            commands += ['no sntp']
            commands += [f"no {line}" for line in device_config.split('\n') if re.match('^sntp server .*', line) != None ]
            
            if os.environ.get('replace',False):
                # remove lines with sntp
                regex = re.compile('^ntp server \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                remove_lines = [f"no {regex.match(line).group(0)}" for line in device_config.split('\n') if regex.match(line) != None ]
                # 
                # drop removals that are planned for deployment                
                commands += [l for l in remove_lines if l not in [line for ntpserver in ntpservers for line in remove_lines if ntpserver in line]]
            
            # configure ntp
            commands += ["timesync ntp", "ntp enable"]
            commands += [f"ntp server {server} burst" for server in ntpservers]
            
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if commands:
                # send commands to device
                device.conn.config_mode()
                for command in commands:
                    device.conn.send_command(command)
                device.conn.exit_config_mode()
                
                config_changed = True
            
        elif device_os == 'arubaos-cx':        
            device = connect(AOS, device_ip, log_prefix)
            if not device: return { 'status': 'FAILED', 'device': log_prefix }
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            if os.environ.get('replace',False):
                # remove lines with sntp
                regex = re.compile('^ntp server \S*')
                remove_lines = [f"no {regex.match(line).group(0)}" for line in device_config.split('\n') if regex.match(line) != None ]
                # 
                # drop removals that are planned for deployment                
                commands += [l for l in remove_lines if l not in [line for ntpserver in ntpservers for line in remove_lines if ntpserver in line]]
            
            # configure ntp
            commands += ["ntp enable"]
            commands += [f"ntp server {server} burst" for server in ntpservers]
            
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if commands:
                # send commands to device
                device.conn.config_mode()
                for command in commands:
                    device.conn.send_command(command)
                device.conn.exit_config_mode()
                
                config_changed = True
            
        elif device_os == 'fs-switch':            
            device = connect(FS, device_ip, log_prefix)
            if not device: return { 'status': 'FAILED', 'device': log_prefix }
            
            device.conn.establish_connection()
            device.conn.read_until_prompt()
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")

            # disable sntp
            if 'sntp' in device_config:
                commands += ['no sntp enable']
                commands += [f"no {line}" for line in device_config.split('\n') if re.match('^sntp server .*', line) != None ]
            
            if os.environ.get('replace',False):
                # remove lines with sntp
                regex = re.compile('^ntp server \S*')
                remove_lines = [f"no {regex.match(line).group(0)}" for line in device_config.split('\n') if regex.match(line) != None ]
                # 
                # drop removals that are planned for deployment                
                commands += [l for l in remove_lines if l not in [line for ntpserver in ntpservers for line in remove_lines if ntpserver in line]]

            # configure ntp
            commands += [f"ntp server {server}" for server in ntpservers]
            
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
        
        # finish up        
        if config_changed:
            device.write_config()
            logger.info(C_YELLOW(f"{log_prefix}: Config changed and saved"))
            logger.debug(C_YELLOW(f"{log_prefix}:\n" + '\n'.join(commands) ))
            device.conn.disconnect()
            return { 'status': 'CHANGED', 'device': log_prefix }
        else:
            logger.info(C_GREEN(f"{log_prefix}: No changes needed"))
            device.conn.disconnect()
            return { 'status': 'UNCHANGED', 'device': log_prefix }
        
    except Exception as e:
        logger.info (C_RED(f"{e}\n\n{log_prefix}: General failure, please contact an engineer to look into the issue, in the mean time check if changes can be done by logging in localy."))
        return { 'status': 'FAILED', 'device': log_prefix }

librenms = LibreNMS()
netbox = Netbox()

lnms_devices = librenms.get_all_devices()
# filter only devices that are up 
lnms_devices = [d for d in lnms_devices if d.get('status') == 1]
lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
#nb_devices = netbox.get_all_devices()
nb_ntpservers = netbox._get_single("/api/extras/config-contexts/?name=ntp").get('results',[{}])[0].get('data',{}).get('ntp',[])

############################
# push changes
############################
results = list(exec_pool(push_change,lnms_devices))

sorted_results = sorted(results, key=lambda d: d['status'])
logger.info('\n'+'\n'.join([str(r) for r in sorted_results]))


# to update librenms run the folling in the database cli:
# UPDATE devices set community='<community>' where os = '<os>';
#

    
    
    
    