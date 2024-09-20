import json
import pathlib
import typing

import netmiko.cisco.cisco_ios
# from ttp import ttp

#from nc_mis import consts
from nc_mis.drivers.abstract import Driver

SCRIPT_DIR = pathlib.Path(__file__).parent
# DATA_DIR = consts.DATA_DIR
# BACKUP_DIR = DATA_DIR.joinpath("backup")
# BACKUP_DIR.mkdir(exist_ok=True)


class FS(Driver):
    def __init__(self, ip: str, username: str, password: str):
        if username and password:
            self.conn = netmiko.cisco.CiscoIosSSH(
                ip=ip, username=username, password=password
            )
        self.username = username
        self.password = password
        self.host = ip

    def send_config_port_profile(self, commands: str | list[str]) -> str:
        pass

    def backup_config(self) -> None:
        output = self.conn.send_command("show run")
        with open(BACKUP_DIR.joinpath(f"{self.conn.host}.cfg"), "w") as file:
            file.write(output)

    def get_config(self) -> str:
        return super().get_config()

    def send_config(self, commands: str | list[str]) -> str:
        return super().send_config(commands)

    def parse_to_openconfig(
        self, config: str | dict = None, file=None
    ) -> dict[str, typing.Any]:
        if config:
            config = config
        elif file:
            config = file
        else:
            config = BACKUP_DIR.joinpath(f"{self.host}.cfg")
        try:
            template = SCRIPT_DIR.joinpath("ttp_templates", "show_run.ttp")
            # print(config)
            # with open(config) as f:
            #     print(f.readlines())
            parser = ttp(data=config, template=str(template))
            parser.parse()
            results = parser.result()[0][0]
            with open(BACKUP_DIR.joinpath(f"{self.host}.oc"), "w") as f:
                f.write(json.dumps(results))
            return results
        except Exception as e:
            print(e)
            pass

    def send_configlet(
        self, commands: str | list[str], dryrun=True, save_config=True
    ) -> str:
        return super().send_configlet(commands, dryrun, save_config)

    def write_config(self):
        return super().write_config()

    def commit(self, save_config=True):
        return super().commit(save_config)

    def rollback(self, name="startup-config") -> None:
        return super().rollback(name)

    def health_check(self) -> None:
        return super().health_check()
