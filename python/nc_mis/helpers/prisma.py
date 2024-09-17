import requests
import logging, os
import ipaddress



class PrismaSDWAN():
    def __init__(self, username=None, password=None, tenant=None, host='https://api.sase.paloaltonetworks.com'):
        self.host = host
        if username and password and tenant:
            self.username = username
            self.password = password
            self.tenant = tenant
        else:
            from dotenv import load_dotenv

            load_dotenv()

            self.username=os.environ.get('PRISMA_USERNAME')
            self.password=os.environ.get('PRISMA_PASSWORD')
            self.tenant=os.environ.get('PRISMA_TENANT')
        if not (self.username and self.password and self.tenant):
            raise Exception('Could not initialize prisma')

        # Init logging
        logging.basicConfig(filename='nc-prisma-collector.log', level=logging.DEBUG)
        self.logger = logging.getLogger("prisma")

        # Prepare api for use
        self.get_token()
        self.get_profile()
         


    def get_token(self):
        oauth_headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        oauth_data = {
            'grant_type': 'client_credentials',
            'scope': f'tsg_id:{self.tenant}',
        }
        r = requests.post(url=f'https://auth.apps.paloaltonetworks.com/oauth2/access_token', headers=oauth_headers, data=oauth_data, auth=(self.username, self.password))

        if not r.ok:
            raise Exception('Error getting token')
        self.token = r.json().get('access_token')

    # Needed to signal we are using unified API
    def get_profile(self):
        prisma_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/json'
        }
        profile = requests.get(url=f'{self.host}/sdwan/v2.1/api/profile', headers=prisma_headers)
        if not profile.ok:
            self.logger.error(profile)
            raise Exception('Error getting profile')
        return profile

    def api_call_get(self, endpoint):
        prisma_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/json'
        }
        r = requests.get(url=f'{self.host}/{endpoint}', headers=prisma_headers)
        return r
    
    def api_call_post(self, endpoint, json):
        prisma_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/json'
        }
        r = requests.post(url=f'{self.host}/{endpoint}', headers=prisma_headers, json=json)
        return r
    
    def api_call_put(self, endpoint, json):
        prisma_headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.token}',
            'Accept': 'application/json'
        }
        r = requests.put(url=f'{self.host}/{endpoint}', headers=prisma_headers, json=json)
        return r

    def get_all_devices(self, force = False):
        # If we have the devices cached and we dont want to renew use the cached list
        if getattr(self, 'devices', None) and force == False:
            return self.devices
        else:
            try:
                r = self.api_call_get(f'sdwan/v2.7/api/elements')
                devices = r.json()['items']
                self.devices = devices
                return devices
            except Exception as e:
                self.logger.error(f'Error getting devices. Error: {e}')
                return None
            
    def get_interfaces(self, device):
        return self.api_call_get(f"sdwan/v4.15/api/sites/{device.get('site_id')}/elements/{device.get('id')}/interfaces").json()['items']
    
    def get_ips(self, device):
        interfaces = self.get_interfaces(device)
        ip_addresses = []
        for interface in interfaces:
            try:
                ip_addresses.append(interface['ipv4_config']['static_config']['address'])
            except TypeError as e:
                pass
        return ip_addresses

    def get_devices(self, subnet):
        if not getattr(self, 'device_info', None):
            self.device_info = {}
        devices = self.get_all_devices()
        result = []
        for device in devices:
            if not device['id'] in self.device_info:
                self.device_info[device['id']] = self.get_interfaces(device)
            interfaces = self.device_info[device['id']]
            for interface in interfaces:
                try:
                    ip = interface.get('ipv4_config',{}).get('static_config',{}).get('address','').split('/')[0]
                except:
                    continue
                if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                    result.append(device)
        return result
            
    def get_security_zones(self, name=None):
        if name:
            zones = self.api_call_get(f"sdwan/v2.0/api/securityzones").json()['items']
            return [x for x in zones if x['name'] == name][0]
        else:
            return self.api_call_get(f"sdwan/v2.0/api/securityzones").json()['items']

    def get_all_sites(self, force = False):
        # If we have the devices cached and we dont want to renew this use the cached list
        if getattr(self, 'sites', None) and force == False:
            return self.sites
        else:
            try:
                r = self.api_call_get(f'sdwan/v4.7/api/sites')
                sites = r.json()['items']
                self.sites = sites
                return sites
            except Exception as e:
                self.logger.error(f'Error getting sites. Error: {e}')
                return None

    
    