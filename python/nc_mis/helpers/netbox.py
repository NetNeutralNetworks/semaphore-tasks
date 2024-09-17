import difflib
import logging
import os
from urllib import parse

import requests

# import pynetbox

class Netbox():
    def __init__(self, host:str|None=None, api_token:str|None=None, port:int|None=None, secure:bool|None=None):
        '''host and api_token are mandatary variables but can be added in dotenv as well.
        If using dotenv use variables NETBOX_HOST, NETBOX_TOKEN, NETBOX_PORT, NETBOX_SECURE'''

        from dotenv import load_dotenv
        load_dotenv(override=True) #TODO seems not reload the environment variables correctly, docker down/up only

        # if variable is explicitly called use it, else check dotenv, else use default port and secure.
        self.host = host if host is not None else os.environ.get('NETBOX_HOST')
        self.api_token= api_token if api_token is not None else os.environ.get('NETBOX_TOKEN')
        self.port = port if port is not None else os.environ.get('NETBOX_PORT', 443)
        self.secure = secure if secure is not None else os.environ.get('NETBOX_SECURE', "True").lower() == "true"

        if not (self.api_token and self.host):
            raise Exception('Could not initialize connection to Netbox API')

        logging.basicConfig(filename='nc-netbox.log', level=logging.DEBUG)

        self.logger = logging.getLogger("netbox")

    def _create_http_headers(self):
        return {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json; indent=4",
        }

    def _get(self, endpoint: str, filter_: dict[str, list[str]] | None = None):
        _,_, path, params, query, fragment = parse.urlparse(endpoint)
        query_dict = parse.parse_qs(query)
        if isinstance(filter_, dict):
            query_dict.update(filter_)
        query_dict['limit'] = ['1000']

        scheme = 'http'
        if self.secure:
            scheme = 'https'
        netloc = f"{self.host}:{self.port}"
        query_string = parse.urlencode(query_dict, doseq=True)
        url_unparsed = (scheme, netloc, path, params, query_string, fragment)

        url = parse.urlunparse(url_unparsed)

        # if "?" in endpoint:
        #     delimiter = "&"
        # else:
        #     delimiter = "?"
        # if self.secure:
        #     URL = f"https://{self.host}:{self.port}{endpoint}{delimiter}limit=1000"
        # else:
        #     URL = f"http://{self.host}:{self.port}{endpoint}{delimiter}limit=1000"
        r = requests.get(url, headers=self._create_http_headers(), verify=self.secure, timeout=3)
        try:
            results = []
            response = r.json()
            results += response["results"]
            while response["next"]:
                print(f"pagination: {response['next']}")
                r = requests.get(
                    response["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                    timeout=3
                )
                response = r.json()
                results += response["results"]

            return results
        except Exception as e:
            self.logger.error(
                f"Error while trying to make a GET request to endpoint: {endpoint}. Error: {e}"
            )
            return None

    def _get_single(self, endpoint):

        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        r = requests.get(URL, headers=self._create_http_headers(), verify=self.secure)
        try:
            response = r.json()
            return response
        except Exception as e:
            self.logger.error(
                f"Error while trying to make a GET request to endpoint: {endpoint}. Error: {e}"
            )
            return None

    def _post(self, endpoint, data):
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        r = requests.post(
            URL, headers=self._create_http_headers(), verify=self.secure, json=data
        )
        try:
            return r.json()
        except Exception as e:
            self.logger.error(
                f"Error while trying to make a POST request to endpoint: {endpoint}. Error: {e}"
            )
            return None

    def _patch(self, endpoint, data):
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        r = requests.patch(
            URL, headers=self._create_http_headers(), verify=self.secure, json=data
        )
        try:
            json_response = r.json()
            if r.status_code != 200:
                return (False, json_response)
            return (True, json_response)
        except Exception as e:
            self.logger.error(
                f"Error while trying to make a PATCH request to endpoint: {endpoint}. Error: {e}"
            )
            return (False, f"Error while trying to make a PATCH request to endpoint: {endpoint}. Error: {e}")

    def get_device(self, hostname):
        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/devices/{hostname}"
        else:
            URL = f"http://{self.host}:{self.port}/api/dcim/devices/{hostname}"
        r = requests.get(URL, headers=self._create_http_headers(), verify=self.secure)
        try:
            return r.json["devices"][0]
        except Exception as e:
            self.logger.error(f"Error getting device: {hostname}. Error: {e}")
            return None

    def get_devicetypes(self):
        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/device-types"
        else:
            URL = f"http://{self.host}:{self.port}/api/dcim/device-types"
        r = requests.get(URL, headers=self._create_http_headers(), verify=self.secure)
        try:
            return r.json["results"]
        except Exception as e:
            self.logger.error(f"Error getting device-types, Error: {e}")
            return None

    def get_all_devices(self):
        results = []
        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/devices/"
        else:
            URL = f"http://{self.host}:{self.port}/api/dcim/devices/"
        try:
            r = requests.get(
                URL, headers=self._create_http_headers(), verify=self.secure
            )
            results += r.json()["results"]
            while r.json()["next"] != None:
                self.logger.debug(r.json()["next"])
                r = requests.get(
                    r.json()["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                )
                results += r.json()["results"]
            return results
        except Exception as e:
            self.logger.error(f"Error getting devices. Error: {e}")
            return None

    def get_devices_from_site(self, site):
        results = []
        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/devices/?site_id={site['id']}"
        else:
            URL = (
                f"http://{self.host}:{self.port}/api/dcim/devices/?site_id={site['id']}"
            )
        try:
            r = requests.get(
                URL, headers=self._create_http_headers(), verify=self.secure
            )
            results += r.json()["results"]
            while r.json()["next"] != None:
                self.logger.debug(r.json()["next"])
                r = requests.get(
                    r.json()["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                )
                results += r.json()["results"]
            return results
        except Exception as e:
            self.logger.error(f"Error getting devices. Error: {e}")
            return None

    def get_all_sites(self):
        results = []
        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/sites/"
        else:
            URL = f"http://{self.host}:{self.port}/api/dcim/sites/"
        try:
            r = requests.get(
                URL, headers=self._create_http_headers(), verify=self.secure
            )
            results += r.json()["results"]
            while r.json()["next"] != None:
                self.logger.debug(r.json()["next"])
                r = requests.get(
                    r.json()["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                )
                results += r.json()["results"]
            return results
        except Exception as e:
            self.logger.error(f"Error getting devices. Error: {e}")
            return None

    def get_site(self, site_id):
        endpoint = f"/api/dcim/sites/{site_id}/"
        results = self._get_single(endpoint)
        return results

    def get_all_prefixes(self):
        results = []
        endpoint = "/api/ipam/prefixes/?limit=200"
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        try:
            r = requests.get(
                URL, headers=self._create_http_headers(), verify=self.secure
            )
            results += r.json()["results"]
            while r.json()["next"] != None:
                self.logger.debug(r.json()["next"])
                r = requests.get(
                    r.json()["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                )
                results += r.json()["results"]
            return results
        except Exception as e:
            self.logger.error(f"Error getting prefixes. Error: {e}")
            return None

    def get_prefixes_from_vrf(self, vrf_id):
        endpoint = f"/api/ipam/prefixes/?vrf_id={vrf_id}"
        results = self._get(endpoint)
        return results

    def get_all_vrfs(self):
        results = []
        endpoint = "/api/ipam/vrfs/"
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        try:
            r = requests.get(
                URL, headers=self._create_http_headers(), verify=self.secure
            )
            results += r.json()["results"]
            while r.json()["next"] != None:
                self.logger.debug(r.json()["next"])
                r = requests.get(
                    r.json()["next"],
                    headers=self._create_http_headers(),
                    verify=self.secure,
                )
                results += r.json()["results"]
            return results
        except Exception as e:
            self.logger.error(f"Error getting vrfs. Error: {e}")
            return None

    def get_all_roles(self):
        endpoint = "/api/ipam/roles/"
        roles = self._get(endpoint)
        return roles

    def get_vlan_groups_with_tag(self, tag):
        endpoint = f"/api/ipam/vlan-groups/?tag={tag}"
        results = self._get(endpoint)
        self.logger.info(f"Got vlan group with tag: {results}")
        return results

    def guess_site(self, name):
        sites = self.get_all_sites()
        site_names = [x["display"] for x in sites]
        best_guess_sites = difflib.get_close_matches(name, site_names, 1, 0.4)
        if len(best_guess_sites) == 0:
            return {"error": f"No match found for {name}"}
        site = [x for x in sites if x["display"] == best_guess_sites[0]][0]
        return site

    def create_device(self, info, site_id):
        devicetypes = self.get_devicetypes()

        device = {
            "name": info["device"]["sysName"],
            "device_type": info["device"]["hardware"],
            "device_role": {"name": "unknown"},
            "serial": info["device"]["serial"],
            "site": site_id,
            # "status": {
            #     "value": "active",
            #     "label": "Active"
            # },
            # "virtual_chassis": null,
            # "vc_position": null,
            # "vc_priority": null,
            "tags": [],
        }

        if self.secure:
            URL = f"https://{self.host}:{self.port}/api/dcim/devices/"
        else:
            URL = f"http://{self.host}:{self.port}/api/dcim/devices/"
        try:
            r = requests.post(
                URL,
                headers=self._create_http_headers(),
                verify=self.secure,
                json=device,
            )
            self.logger.info(f"request: {r} ; {r.json()}")
            if r.ok:
                print("SUCCES!")
        except Exception as e:
            self.logger.error(f"Error creating device. Error: {e}")
            return None

    def create_prefix(self, info):
        endpoint = "/api/ipam/prefixes/"
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        try:
            r = requests.post(
                URL, headers=self._create_http_headers(), verify=self.secure, json=info
            )
            self.logger.info(f"request: {r} ; {r.json()}")
            return r.json()
        except Exception as e:
            self.logger.error(f"Error creating prefix. Error: {e}")
            return None

    def create_prefix_from_parent(self, parent_id, **kwargs):
        endpoint = f"/api/ipam/prefixes/{parent_id}/available-prefixes/"
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        try:
            r = requests.post(
                URL,
                headers=self._create_http_headers(),
                verify=self.secure,
                json=kwargs,
            )
            self.logger.info(f"request: {r} ; {r.json()}")
            if r.ok:
                print("SUCCES!")
            return r.json()
        except Exception as e:
            self.logger.error(f"Error creating prefix from parent. Error: {e}")
            return e

    def create_vlan_from_group(self, group_id, **kwargs):
        endpoint = f"/api/ipam/vlan-groups/{group_id}/available-vlans/"
        result = self._post(endpoint=endpoint, data=kwargs)
        self.logger.info(f"Got vlan from group: {result}")
        return result

    def create_vrf(self, **kwargs):
        endpoint = f"/api/ipam/vrfs/"
        if self.secure:
            URL = f"https://{self.host}:{self.port}{endpoint}"
        else:
            URL = f"http://{self.host}:{self.port}{endpoint}"
        try:
            r = requests.post(
                URL,
                headers=self._create_http_headers(),
                verify=self.secure,
                json=kwargs,
            )
            self.logger.info(f"request: {r} ; {r.json()}")
            if r.ok:
                print("SUCCES!")
            return r.json()
        except Exception as e:
            self.logger.error(f"Error creating VRF. Error: {e}")
            return None
