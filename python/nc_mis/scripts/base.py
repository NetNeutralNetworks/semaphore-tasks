import os

import yaml

from nc_mis.drivers.abstract import Platform
from nc_mis.drivers.aruba.aos.AOS import AOS
from nc_mis.drivers.fs.fs import FS
from nc_mis.drivers.hp.procurve import PROCURVE
from nc_mis.drivers.juniper.JUNOS import JUNOS
from nc_mis.helpers.librenms import LibreNMS


def get_credentials():
    with open(
        os.getenv(
            "NC_ACCELERATOR_CREDENTIALS", "/etc/ncubed/nc-accelerator/credentials.yaml"
        ),
        "r",
        encoding="utf-8",
    ) as f:
        credentials = yaml.safe_load(f)

    return credentials.get("users", {}).get("default", {})


class Script:
    required_args = []
    optional_args = []
    supported_platforms = []

    def __init__(self, **kwargs):
        for arg in self.required_args:
            if not kwargs.get(arg):
                raise Exception(
                    f"Not all required arguments are present: {arg} is missing"
                )
        self.arguments = kwargs

    def execute(self, device_info):
        pass

    def post_add(self):
        pass

    def pre_run(self):
        pass


class DesiredStateScript(Script):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class MultiScript(Script):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class ExampleScript(Script):
    required_args = ["text"]
    optional_args = []
    supported_platforms = [Platform.IOS, Platform.ARUBAOS_CX, Platform.HP_PROCURVE]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        return f"ExampleScript Passed: {self.arguments.get('text')}"


class NCJob:
    scripts: list[Script]

    def __init__(self, device_info, config_strat="libre"):
        self.device_info = device_info
        self.scripts = []
        user = get_credentials()
        self.libre = LibreNMS()
        if device_info.get("platform") == Platform.ARUBAOS_CX:
            self.driver = AOS(
                ip=device_info.get("host"),
                username=user.get("username", ""),
                password=user.get("password", ""),
            )
        elif device_info.get("platform") == Platform.JUNOS:
            self.driver = JUNOS(
                ip=device_info.get("host"),
                username=user.get("username", ""),
                password=user.get("password", ""),
            )
        elif device_info.get("platform") == Platform.HP_PROCURVE:
            self.driver = PROCURVE(
                ip=device_info.get("host"),
                username=user.get("username", ""),
                password=user.get("password", ""),
            )
        elif device_info.get("platform") == Platform.FS:
            self.driver = FS(
                ip=device_info.get("host"),
                username=user.get("username", ""),
                password=user.get("password", ""),
            )
        elif device_info.get("platform") == Platform.IOS:
            self.driver = FS(
                ip=device_info.get("host"),
                username=user.get("username", ""),
                password=user.get("password", ""),
            )

        # if config_strat == 'libre':
        #     try:
        #         self.config = "".join(self.libre.get_device_config(device_info.get('host')))
        #         self.oc = self.driver.parse_to_openconfig(self.config)
        #     except:
        #         self.config = None
        #         self.oc = None

        # if config_strat == 'node':
        #     try:
        #         self.config = self.driver.get_config()
        #         self.oc = self.driver.parse_to_openconfig(self.config)
        #     except:
        #         self.config = None
        #         self.oc = None

    def add_script(self, script: Script):
        if (
            self.device_info.get("platform") not in script.supported_platforms
        ) and not ("*" in script.supported_platforms):
            raise Exception(
                f"Script: {type(script).__name__} does not support platform: {self.device_info.get('platform')}"
            )
        script.job = self
        if isinstance(script, MultiScript):
            script.expand()
        script.platform = self.device_info.get("platform")
        self.scripts.append(script)

    def execute_scripts(self):
        self.output = []
        for script in self.scripts:
            self.output += script.execute(self.device_info)

        self.result = self.driver.send_configlet(self.output, dryrun=False)
