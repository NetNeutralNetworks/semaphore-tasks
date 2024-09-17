import yaml
import argparse
import os
from nc_mis.helpers.netbox import Netbox
import ipaddress

netbox = Netbox()
# get devices from netbox
# f"https://{os.environ.get('NETBOX_HOST','')}/api/dcim/devices/?device_role=switch&manufacturer=hpe"
#
nb_devices = netbox.get_all_devices()

for nb_device in nb_devices:
    if nb_device.get('device_type').get('manufacturer').get('slug') == 'hpe' and nb_device.get('device_role').get('slug') == 'switch':        
        from nc_mis.drivers.hp.procurve import PROCURVE
        try:
            host = nb_device.get('primary_ip',{}).get('address').split('/')[0]
            device = PROCURVE(ip=f"{os.environ.get('V6_PREFIX')}{host}",
                                username=os.environ.get('device_username',''),
                                password=os.environ.get('device_password','')
                                )
        except:
            print ("Management ip not specified in netbox")
            continue
        

        device_config = device.get_config()
        
        # prep commands
        commands = []
        logservers = nb_device.get('config_context').get('logservers')
        if os.environ.get('replace',False):
            remove_lines = [f"no {line}" for server in logservers for line in device_config.split('\n') if 'logging' in line]
            commands += [line for server in logservers for line in remove_lines if server not in line]
            logservers = [server for server in logservers for line in remove_lines if server not in line]
            
        commands += [f"logging {s}"for s in logservers]
        if not commands:
            print(f"{host}: No changes needed")
            continue
        # send commands to device
        result = device.send_config(commands)

        device.write_config()
        
        print(f"{host}: Config changed and saved")
        
    else:
        print("No manufacturer set or device is not a switch")
    