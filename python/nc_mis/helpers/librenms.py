import requests
import logging
import os
import ipaddress


class LibreNMS():
    device_mapping_to_netbox = {
        'Juniper VSRX Internet Router': 'vSRX',
        'Juniper VQFX-10000': 'vQFX',
        'J9776A 2530-24G':'Aruba 2530-24G',
        'PA-3050':'PA-3050',
        'J9773A 2530-24G-PoEP':'Aruba 2530-24G-PoE+',
        'J9772A 2530-48G-PoEP':'Aruba 2530-48G-PoE+',
        'J9727A 2920-24G-PoE+': 'Aruba 2920-24G-PoE+',
        'J9729A 2920-48G-POE+': 'Aruba 2920-48G-PoE+',
        '2530-48G-PoEP': 'Aruba 2530-48G-PoE+',

    }
    def __init__(self, host=None, api_token=None, port=443, secure=True):
        if host and api_token:
            self.host = host
            self.api_token = api_token
        else:
            from dotenv import load_dotenv

            load_dotenv(override=True)

            self.host=os.environ.get('LIBRENMS_HOST')
            self.api_token=os.environ.get('LIBRENMS_TOKEN')
        self.port = port
        self.secure = secure

        logging.basicConfig(filename='nc-librenms-collector.log', level=logging.DEBUG)

        self.logger = logging.getLogger("librenms")

    def api_call_get(self, endpoint):
        if self.secure:
            URL = f'https://{self.host}:{self.port}/{endpoint}'
        else:
            URL = f'http://{self.host}:{self.port}/{endpoint}'
        r = requests.get( 
            URL,
            headers={'X-Auth-Token': self.api_token},
            verify=self.secure
        )
        return r
    

    def get_device(self, hostname):
        try:
            r = self.api_call_get(f'api/v0/devices/{hostname}')
            return r.json()['devices'][0]
        except Exception as e:
            self.logger.error(f'Error getting device: {hostname}. Error: {e}')
            return None

    def get_all_devices(self):
        try:
            r = self.api_call_get(f'api/v0/devices')
            return r.json()['devices']
        except Exception as e:
            self.logger.error(f'Error getting all devices. Error: {e}')
            return None

    
    def get_device_config(self, hostname):
        try:
            r = self.api_call_get(f'api/v0/oxidized/config/{hostname}')
            return r.json()['config']
        except Exception as e:
            self.logger.error(f'Error getting config from device: {hostname}. Error: {e}')
            return None
        
    def get_switch_interlinks(self, hostname, hostname_search = None):
        try:
            output = []
            r = self.api_call_get(f'api/v0/devices/{hostname}/links')
            neighbors = r.json()['links']
            for neighbor in neighbors:
                if neighbor.get('remote_device_id') and neighbor.get('remote_device_id') != 0:
                    output.append(neighbor)
                elif hostname_search and hostname_search in neighbor.get('remote_hostname', ''):
                    output.append(neighbor)
            return output
        except Exception as e:
            self.logger.error(f'Error getting neighbors from device: {hostname}. Error: {e}')
            return None
        
    def get_port_info(self, portID):
        try:
            r = self.api_call_get(f'api/v0/ports/{portID}')
            return r.json()['port'][0]
        except Exception as e:
            self.logger.error(f'Error getting config from port: {portID}. Error: {e}')
            return None
        
    def get_arp_info(self, query):
        try:
            r = self.api_call_get(f'api/v0/resources/ip/arp/{query}')
            return r.json()['arp']
        except Exception as e:
            self.logger.error(f'Error getting ARP results for: {query}. Error: {e}')
            return None
        
    def get_subnets(self, mask):
        subnets = []
        ips = [ x['hostname'] for x in self.get_all_devices() if x['type'] == 'network']
        for ip in ips:
            subnet = ipaddress.ip_interface(f"{ip}/{mask}")
            if not str(subnet.network) in subnets:
                subnets.append(str(subnet.network))
        return subnets
    
    def get_devices_in_subnet(self, subnet):
        if isinstance(subnet, ipaddress.IPv4Network) or isinstance(subnet, ipaddress.IPv6Network):
            pass
        elif isinstance(subnet, ipaddress.IPv4Interface) or isinstance(subnet, ipaddress.IPv6Interface):
            subnet = subnet.network	
        elif isinstance(subnet, str):
            try:
                subnet = ipaddress.ip_network(subnet)
            except:
                try:
                    subnet = ipaddress.ip_interface(subnet).network
                except:
                    raise TypeError(f"{subnet} is not a network")
        else:
            raise TypeError(f"{subnet} should be a string, ip_network or ip_interface")
        
        results = []
        for device in self.get_all_devices():
            device_ip = ipaddress.ip_address(device['hostname'])
            if device_ip in subnet:
                results.append(device)
        return results
    
    def get_inventory_info(self, host):
        try:
            r = self.api_call_get(f'api/v0/inventory/{host}/all')
            return r.json()['inventory']
        except Exception as e:
            self.logger.error(f'Error getting inventry from device: {host}. Error: {e}')
            return None
        
    def get_device_ports(self, host):
        try:
            r = self.api_call_get(f'api/v0/devices/{host}/ports?columns=port_id,device_id,ifName,ifAdminStatus,ifAlias')
            return r.json()['ports']
        except Exception as e:
            self.logger.error(f'Error getting ports from device: {host}. Error: {e}')
            return None
        
    def get_device_ips(self, host):
        try:
            r = self.api_call_get(f'api/v0/devices/{host}/ip')
            return r.json()['addresses']
        except Exception as e:
            self.logger.error(f'Error getting ip addresses from device: {host}. Error: {e}')
            return None
    
    def get_extended_device_info(self, host):
        device = self.get_device(host)

        inventory = self.get_inventory_info(host)
        hp_stacks = sorted([item for item in inventory if item.get('entPhysicalClass') == 'chassis'], key=lambda item: item['entPhysicalIndex'])
        juniper_stacks = [item for item in inventory if 'fpc' in item.get('entPhysicalDescr').lower()]

        stacks = hp_stacks + juniper_stacks

        ports = self.get_device_ports(host)
        # print(ports)

        ip_info = self.get_device_ips(host)
        # print(ip_info)

        for ip in ip_info or []:
            port = [x for x in ports if x['port_id'] == ip['port_id']][0]
            port['ip_info'] = ip

        result = {
            'device': device,
            'stacks': stacks,
            'ports': ports
        }
        return result

