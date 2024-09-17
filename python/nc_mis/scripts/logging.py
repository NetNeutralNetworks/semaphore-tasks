from scripts.base import Script

class SetLogServersScript(Script):
    required_args = ["oc"]
    optional_args = ["log_servers"]
    supported_platforms = ['arubaos-cx']
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        output = []
        if self.platform == 'arubaos-cx':
            
            current_log_servers = self.arguments.get('oc', {}).get('system', {}).get('logging', {}).get('remote-servers',{}).get('remote-server', {})
            desired_log_servers = self.arguments.get('log_servers')
            # Remove unwanted log servers
            for current_log_server in current_log_servers:
                if current_log_server not in desired_log_servers:
                    output.append(f'no logging {current_log_server}')
            # Add servers that are not added
            for desired_log_server in desired_log_servers:
                if desired_log_server not in current_log_servers:
                    output.append(f'logging {desired_log_server}')
            return output