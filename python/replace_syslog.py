import yaml
import argparse
import os
import re
from time import sleep
from nc_mis.helpers.netbox import Netbox
from nc_mis.helpers.librenms import LibreNMS

import ipaddress

from nc_mis.drivers.hp.procurve import PROCURVE
from nc_mis.drivers.aruba.aos import AOS
import concurrent.futures
import multiprocessing

MAX_WORKERS = os.environ.get('MAX_WORKERS',multiprocessing.cpu_count())

def exec_pool(FUNCTION,LIST):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(FUNCTION,LIST)

def puch_change(nb_device):
    try:
        lnms_device = lnms_devices.get(nb_device.get('display',''))
        if not lnms_device:
            return
        device_manufacturer = nb_device.get('device_type').get('manufacturer').get('slug')
        #device_role = nb_device.get('device_role').get('slug')
        device_os = lnms_device.get('os')
        device_ip = lnms_device.get('ip')
        #devcie_ip = nb_device.get('primary_ip').get('address').split('/')[0]
        
        if device_manufacturer == 'hpe' and device_os == 'procurve':        
            try:
                device = PROCURVE(ip=f"{os.environ.get('V6_PREFIX','')}{device_ip}",
                                    username=os.environ.get('device_username',''),
                                    password=os.environ.get('device_password','')
                                    )
            except:
                print (f"{nb_device.get('display')},{device_ip}: Management ip not found or failed to authenticate")
                return
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_config = device.conn.send_command("show run")
            
            # prep commands
            commands = []
            logservers = nb_device.get('config_context').get('logservers')
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
                print(f"{nb_device.get('display')},{device_ip}: No changes needed")
                return
            
            # send commands to device
            device.conn.config_mode()
            for command in commands:
                device.conn.send_command(command)
            device.conn.exit_config_mode()
            
            device.conn.send_command('write memory')
            device.conn.disconnect()
            
            print(f"{nb_device.get('display')},{device_ip}: Config changed and saved")
            
        if nb_device.get('device_type').get('manufacturer').get('slug') == 'aruba' and nb_device.get('device_role').get('slug') == 'switch':
            
            try:
                host = nb_device.get('primary_ip').get('address').split('/')[0]
                device = AOS(ip=f"{os.environ.get('V6_PREFIX','')}{host}",
                                    username=os.environ.get('device_username',''),
                                    password=os.environ.get('device_password','')
                                    )
            except:
                print (f"{nb_device.get('display')},{nb_device.get('primary_ip')}: Management ip not specified in netbox")
                return
            
            print(f"{host}: Config changed and saved")
            
        else:
            if os.environ.get('DEBUG',False):
                print(f"{nb_device.get('display')}: No manufacturer set or device is not a switch")
            return
    except Exception as e:
        print (f"{e}\n\n{nb_device.get('display')},{nb_device.get('primary_ip')}: Failure in communication, please contact an engineer to look in to the issue, in the mean time check if changes can be done by logging in localy.")

librenms = LibreNMS()
netbox = Netbox()
# get devices from netbox
# f"https://{os.environ.get('NETBOX_HOST','')}/api/dcim/devices/?device_role=switch&manufacturer=hpe"
#

lnms_devices = librenms.get_all_devices()
lnms_devices = {d['sysName'].split('.')[0]:d for d in lnms_devices}
nb_devices = netbox.get_all_devices()

############################
# push changes
############################
exec_pool(puch_change,nb_devices)
    
    
    
    