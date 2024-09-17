from .base import Script

class AddMGMTWhitelistScript(Script):
    required_args = ["ip"]
    optional_args = ["subnet", "access"]
    supported_platforms = ['hp_procurve']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        output = []
        if self.platform == 'hp_procurve':
            if self.arguments.get('subnet'):
                subnet = self.arguments.get('subnet')
            else:
                subnet = '255.255.255.255'
            output.append(f"ip authorized-managers {self.arguments.get('ip')} {subnet} access {self.arguments.get('access', 'manager')}")
        return output