import yaml
import argparse
import os
from nc_mis.helpers.netbox import Netbox
from nc_mis.helpers.librenms import LibreNMS
import ipaddress

# Expected environmental variables: 
# NETBOX_HOST
# NETBOX_TOKEN
# LIBRENMS_HOST 
# LIBRENMS_TOKEN

netbox = Netbox()
librenms = LibreNMS()
# get devices from netbox
# f"https://{os.environ.get('NETBOX_HOST','')}/api/dcim/devices/?device_role=switch&manufacturer=hpe"
#
lmns_devices = librenms.get_all_devices()
nb_devices = netbox.get_all_devices()



pass