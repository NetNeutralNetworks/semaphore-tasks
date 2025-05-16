import yaml
import argparse
import os, sys
import logging
from nc_helpers.netbox import Netbox
from nc_helpers.librenms import LibreNMS
from nc_helpers.diffsync_definition.adapters import LibreNMSDeviceAdapter,NetboxDeviceAdapter


logger = logging.getLogger('nc-mis')
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
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
lnms_adapter = LibreNMSDeviceAdapter(librenms)
lnms_adapter.load()
netbox_adapter = NetboxDeviceAdapter(netbox)
netbox_adapter.load()

diff = lnms_adapter.diff_to(netbox_adapter)

logging.info(diff.str())