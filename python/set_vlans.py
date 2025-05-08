
import subprocess, sys, traceback
subprocess.run([sys.executable, "-m", "pip", "install", "-r", "python/requirements.txt"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

import yaml
import argparse
import os
import sys
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
logger.setLevel(logging.DEBUG)
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

        netbox_device = netbox_devices_map.get(lnms_device.get('sysName'),{})
        netbox_device_id = netbox_device.get('id')
        if not netbox_device_id:
            if os.environ.get('DEBUG',False):
                logger.info(f"{log_prefix}: Cannot find device in netbox")
            return { 'status': 'IGNORED', 'device': log_prefix }
        config_context = netbox._get_single(f"/api/dcim/devices/{netbox_device_id}")['config_context']
        desired_vlan_config = config_context.get('vlans', {})

        vlans = netbox_sites.get(netbox_device.get('site', {}).get('name'), default=set())

        
        
        
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
            device_openconfig = device.parse_to_openconfig(config=device_config)

            configured_vlans = [x.get('vlan-id') for x in device_openconfig.get('vlans', [])]
            
            for vlan in desired_vlan_config:
                if vlan['vlan-id'] in configured_vlans:
                    # Already exists
                    continue
                commands += [f"""vlan {vlan['vlan-id']}"""]
                commands += [f"""name {vlan.get('config', {}).get('name', '')}"""]
                commands += [f"""exit"""]
            
            
        elif device_os == 'arubaos-cx':        
            device = connect(AOS, device_ip, log_prefix)
            if not device: return { 'status': 'FAILED', 'device': log_prefix }
            
            device.conn.establish_connection()
            device.conn.read_until_prompt_or_pattern('Press any key to continue')
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            device_openconfig = device.parse_to_openconfig(config=device_config)

            configured_vlans = [x.get('vlan-id') for x in device_openconfig.get('vlans', [])]
            
            for vlan in desired_vlan_config:
                if vlan['vlan-id'] in configured_vlans:
                    # Already exists
                    continue
                commands += [f"""vlan {vlan['vlan-id']}"""]
                commands += [f"""name {vlan.get('config', {}).get('name', '')}"""]
                commands += [f"""exit"""]
            
        elif device_os == 'fs-switch':            
            device = connect(FS, device_ip, log_prefix)
            if not device: return { 'status': 'FAILED', 'device': log_prefix }
            
            device.conn.establish_connection()
            device.conn.read_until_prompt()
            device.conn.read_channel()
            device.conn.enable()

            device_version = device.conn.send_command("show version")
            device_config = device.conn.send_command("show run")
            device_openconfig = device.parse_to_openconfig(config=device_config)

            configured_vlans = [x.get('vlan-id') for x in device_openconfig.get('vlans', [])]
            
            for vlan in desired_vlan_config:
                if vlan['vlan-id'] in configured_vlans:
                    # Already exists
                    continue
                commands += [f"""vlan {vlan['vlan-id']}"""]
                commands += [f"""name {vlan.get('config', {}).get('name', '')}"""]
                commands += [f"""exit"""]
            
            
        else:
            if os.environ.get('DEBUG',False):
                logger.info(f"{log_prefix}: No manufacturer set or device is not a switch")
            return { 'status': 'IGNORED', 'device': log_prefix }
        
        site_vlans = netbox_sites.get(netbox_device.get('site', {}).get('name'))
        if not site_vlans:
            site_vlans = set()
        site_vlans.update(configured_vlans)
        netbox_sites[netbox_device.get('site', {}).get('name')] = site_vlans
        
        # finish up 
        if commands:           
            # send commands to device
            # device.conn.config_mode()
            # for command in commands:
            #     device.conn.send_command(command)
            # device.conn.exit_config_mode()
            config_changed = True       
        if config_changed:
            # device.write_config()
            logger.info(C_YELLOW(f"{log_prefix}: Config changed: {commands}"))
            device.conn.disconnect()
            return { 'status': 'CHANGED', 'device': log_prefix }
        else:
            logger.info(C_GREEN(f"{log_prefix}: No changes needed"))
            device.conn.disconnect()
            return { 'status': 'UNCHANGED', 'device': log_prefix }
        
    except Exception as e:
        logger.info (C_RED(f"{e}\n\n{log_prefix}: General failure, please contact an engineer to look into the issue, in the mean time check if changes can be done by logging in localy.\n {traceback.format_exc()}"))
        return { 'status': 'FAILED', 'device': log_prefix }

librenms = LibreNMS()
netbox = Netbox()

lnms_devices = librenms.get_all_devices()
netbox_devices = netbox.get_all_devices()
# filter only devices that are up 
#lnms_devices = [d for d in lnms_devices if d.get('status') == 1]
lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
netbox_devices_map = {d['name']:d for d in netbox_devices}

netbox_sites = {}

############################
# push changes
############################
results = list(exec_pool(push_change,lnms_devices))

logger.info(str(netbox_sites))


sorted_results = sorted(results, key=lambda d: d['status'])
logger.info('\n'+'\n'.join([str(r) for r in sorted_results]))


# to update librenms run the folling in the database cli:
# UPDATE devices set community='<community>' where os = '<os>';
#

    
    
    
    