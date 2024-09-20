import yaml
import argparse
import os
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

MAX_WORKERS = os.environ.get('MAX_WORKERS',multiprocessing.cpu_count()*2)
print(f"Using {MAX_WORKERS} workers")

def exec_pool(FUNCTION,LIST):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(FUNCTION,LIST)

def puch_change(lnms_device):
    try:
        #lnms_device = lnms_devices.get(nb_device.get('display',''))
        # if not lnms_device:
        #     return
        #device_manufacturer = nb_device.get('device_type').get('manufacturer').get('slug')
        #device_role = nb_device.get('device_role').get('slug')
        device_os = lnms_device.get('os')
        device_ip = f"{os.environ.get('V6_PREFIX','')}{lnms_device.get('ip')}"
        device_name = lnms_device.get('sysName')
        #devcie_name = nb_device.get('display')
        logservers = nb_logservers #nb_device.get('config_context').get('logservers')
        #devcie_ip = nb_device.get('primary_ip').get('address').split('/')[0]
        
        log_prefix = f"{device_name}, {device_ip}, {device_os}"
        
        if device_os == 'procurve':        
            try:
                device = PROCURVE(ip=device_ip,
                                    username=os.environ.get('device_username',''),
                                    password=os.environ.get('device_password','')
                                    )
            except:
                print (f"{log_prefix}: Management ip not found or failed to authenticate")
                return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_config = device.conn.send_command("show run")
            
            # prep commands
            commands = []
            
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if re.match('^logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) != None ]
                # drop removals that are planned for deployment
                commands += [line for server in logservers for line in remove_lines if server not in line]
            
            commands += [f"logging {s}"for s in logservers]
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if not commands:
                device.conn.disconnect()
                print(f"{log_prefix}: No changes needed")
                return
            
            # send commands to device
            device.conn.config_mode()
            for command in commands:
                device.conn.send_command(command)
            device.conn.exit_config_mode()
            
            device.conn.send_command('write memory')
            device.conn.disconnect()
            
            print(f"{log_prefix}: Config changed and saved")
            
        elif device_os == 'arubaos-cx':        
            try:
                device = AOS(ip=device_ip,
                                    username=os.environ.get('device_username',''),
                                    password=os.environ.get('device_password','')
                                    )
            except:
                print (f"{log_prefix}: Management ip not found or failed to authenticate")
                return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            # prep commands
            commands = []
            
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if re.match('^logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) != None ]
                # drop removals that are planned for deployment
                commands += [line for server in logservers for line in remove_lines if server not in line]
            
            commands += [f"logging {s}"for s in logservers]
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if not commands:
                device.conn.disconnect()
                print(f"{log_prefix}: No changes needed")
                return
            
            # send commands to device
            device.conn.config_mode()
            for command in commands:
                device.conn.send_command(command)
            device.conn.exit_config_mode()
            
            # aos is really slow to write the config so it needs some extra time
            device.conn.send_command('write memory',read_timeout=30)
            device.conn.disconnect()
            
            print(f"{log_prefix}: Config changed and saved")
            
        elif device_os == 'fs-switch':
            
            try:
                device = FS(ip=device_ip,
                             username=os.environ.get('device_username',''),
                             password=os.environ.get('device_password','')
                            )
            except:
                print (f"{log_prefix}: Management ip not found or failed to authenticate")
                return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt()
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            
            # prep commands
            commands = []
            
            if os.environ.get('replace',False):
                # find all config lines that match "logging <ip>"
                remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if re.match('^logging server \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line) != None ]
                # drop removals that are planned for deployment
                commands += [line for server in logservers for line in remove_lines if server not in line]
            
            commands += [f"logging server {s}"for s in logservers]
            # drop deployments that are allready in the config
            commands = [command for command in commands if command not in device_config]
            
            if not commands:
                device.conn.disconnect()
                print(f"{log_prefix}: No changes needed")
                return
            
            # send commands to device
            device.conn.config_mode()
            for command in commands:
                device.conn.send_command(command)
            device.conn.exit_config_mode()
            
            device.conn.send_command('write memory',read_timeout=30)
            device.conn.disconnect()
            
            print(f"{log_prefix}: Config changed and saved")
            
        else:
            if os.environ.get('DEBUG',False):
                print(f"{log_prefix}: No manufacturer set or device is not a switch")
            return
    except Exception as e:
        print (f"{e}\n\n{log_prefix}: General failure, please contact an engineer to look in to the issue, in the mean time check if changes can be done by logging in localy.")
    return

librenms = LibreNMS()
netbox = Netbox()

lnms_devices = librenms.get_all_devices()
lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
#nb_devices = netbox.get_all_devices()
nb_logservers = netbox._get_single("/api/extras/config-contexts/?name=logservers").get('results',[{}])[0].get('data',{}).get('logservers',[])

############################
# push changes
############################
exec_pool(puch_change,lnms_devices)
    
    
    
    