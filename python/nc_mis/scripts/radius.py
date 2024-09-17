from nc_mis.scripts.base import Script
from nc_mis.drivers.abstract import Platform

class AddRadiusServerScript(Script):
    required_args = ["radius_server", "radius_secret"]
    optional_args = []
    supported_platforms = [Platform.HP_PROCURVE, Platform.ARUBAOS_CX, Platform.FS]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        output = []
        if self.platform == Platform.HP_PROCURVE:
            address = self.arguments.get('radius_server')
            key = self.arguments.get('radius_secret')
            output.append(f'radius-server host {address} key {key}')
            return output
        elif self.platform == Platform.ARUBAOS_CX:
            address = self.arguments.get('radius_server')
            key = self.arguments.get('radius_secret')
            output.append(f'radius-server host {address} key plaintext {key}')
            return output
        elif self.platform == Platform.FS:
            address = self.arguments.get('radius_server')
            key = self.arguments.get('radius_secret')
            output.append(f'radius-server host {address} key 0 {key}')
            return output
    