from .base import Script, MultiScript

class AddVlanScript(Script):
    required_args = ["vlan_id"]
    optional_args = ["description"]
    supported_platforms = ['arubaos-cx', 'hp_procurve']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        output = []
        if self.platform == 'arubaos-cx':
            output.append(f"vlan {self.arguments.get('vlan_id')}")
            if self.arguments.get('description'):
                output.append(f"description {self.arguments.get('description')}")
            output.append("exit")
            return output
        elif self.platform == 'hp_procurve':
            output.append(f"vlan {self.arguments.get('vlan_id')}")
            if self.arguments.get('description'):
                output.append(f"""name '{self.arguments.get('description')}'""")
            output.append("exit")
            return output
        
class RemoveVlanScript(Script):
    required_args = ["vlan_id"]
    optional_args = []
    supported_platforms = ['arubaos-cx']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        if self.platform == 'arubaos-cx':
            output = []
            output.append(f"no vlan {self.arguments.get('vlan_id')}")
            output.append("exit")
            return output
        elif self.platform == 'hp_procurve':
            output = []
            output.append(f"no vlan {self.arguments.get('vlan_id')}")
            output.append("exit")
            return output
        
class AddTrunkVlanScript(Script):
    required_args = ["vlan_id", "interface"]
    optional_args = []
    supported_platforms = ['arubaos-cx', 'hp_procurve']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        if self.platform == 'arubaos-cx':
            output = []
            output.append(f"interface {self.arguments.get('interface')}")
            output.append(f"vlan trunk allowed {self.arguments.get('vlan_id')}")
            output.append("exit")
            return output
        elif self.platform == 'hp_procurve':
            output = []
            output.append(f"vlan {self.arguments.get('vlan_id')}")
            output.append(f"tagged {self.arguments.get('interface')}")
            output.append("exit")
            return output
        
class RemoveTrunkVlanScript(Script):
    required_args = ["vlan_id", "interface"]
    optional_args = []
    supported_platforms = ['arubaos-cx']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        if self.platform == 'arubaos-cx':
            output = []
            output.append(f"interface {self.arguments.get('interface')}")
            output.append(f"no vlan trunk allowed {self.arguments.get('vlan_id')}")
            output.append("exit")
            return output
        elif self.platform == 'hp_procurve':
            output = []
            output.append(f"vlan {self.arguments.get('vlan_id')}")
            output.append(f"no tagged {self.arguments.get('interface')}")
            output.append("exit")
            return output

class AddVlanToSwitchAndInterlinksScript(MultiScript):
    required_args = ["vlan_id"]
    optional_args = ["description"]
    supported_platforms = ['*']
    def __init__(self, **kwargs):
        if 'hostname_search' in kwargs:
            self.hostname_search = kwargs['hostname_search']
        super().__init__(**kwargs)
        
    def expand(self):
        if self.hostname_search:
            neighbors = self.job.libre.get_switch_interlinks(self.job.device_info.get('host'), hostname_search = self.hostname_search)
        else:
            neighbors = self.job.libre.get_switch_interlinks(self.job.device_info.get('host'))
        if not neighbors:
            return
        self.job.add_script(AddVlanScript(vlan_id=self.arguments.get('vlan_id'), description=self.arguments.get('description')))
        for neighbor in neighbors:
            port = self.job.libre.get_port_info(neighbor.get('local_port_id')).get('ifName')
            self.job.add_script(AddTrunkVlanScript(vlan_id=self.arguments.get('vlan_id'), interface=port))
        
    def execute(self, device_info):
        return []