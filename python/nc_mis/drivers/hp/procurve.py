import json
import pathlib
import re
import time
import typing

import netmiko.hp.hp_procurve
from netmiko import ConnectHandler
from paramiko import AutoAddPolicy, SSHClient
from scp import SCPClient
#from ttp import ttp

#from nc_mis import consts
from nc_mis.drivers.abstract import Driver

SCRIPT_DIR = pathlib.Path(__file__).parent
#DATA_DIR = consts.DATA_DIR
#BACKUP_DIR = DATA_DIR.joinpath("backup")
#BACKUP_DIR.mkdir(exist_ok=True)


class PROCURVE(Driver):
    def __init__(self, ip: str, username: str, password: str):
        if username and password:
            self.conn = netmiko.hp.HPProcurveSSH(
                ip=ip, username=username, password=password
            )
        self.username = username
        self.password = password
        self.host = ip

    def send_config_port_profile(self, commands: str | list[str]) -> str:
        pass

    def backup_config(self) -> None:
        with self.conn as net_connect:
            net_connect.enable()
            net_connect.config_mode()
            net_connect.send_command("ip ssh filetransfer")

        with SSHClient() as ssh:
            ssh.set_missing_host_key_policy(AutoAddPolicy)
            ssh.connect(
                hostname=self.host,
                username=self.username,
                password=self.password,
                allow_agent=False,
                look_for_keys=False,
            )
            with SCPClient(ssh.get_transport()) as scp:
                scp.get(
                    "cfg/running-config",
                    str(BACKUP_DIR.joinpath(f"{self.conn.host}.cfg")),
                )

    def get_config(self) -> str:
        with self.conn as net_connect:
            output = net_connect.send_command("show run")
        return output

    def send_config(self, commands: str | list[str]):
        with self.conn as net_connect:
            net_connect.establish_connection()
            net_connect.enable()
            net_connect.config_mode()
            for command in commands:
                net_connect.send_command(command)

    def parse_to_openconfig(
        self, config: str | dict = None, file=None
    ) -> dict[str, typing.Any]:
        if config:
            config = config
        elif file:
            config = file
        else:
            config = str(BACKUP_DIR.joinpath(f"{self.host}.cfg"))
        try:
            template = SCRIPT_DIR.joinpath("ttp_templates", "show_run.ttp")
            # print(config)
            # with open(config) as f:
            #     print(f.readlines())
            parser = ttp(data=config, template=str(template))
            parser.add_function(
                match_stacked_range, scope="match", name="stacked_unrange"
            )
            parser.parse()
            results = parser.result()[0][0]
            interfaces = {}
            for interface in results.get("interfaces", []):
                interfaces[interface.get("name")] = interface
            # Add vlan interfaces
            for vlan in results.get("vlans", []):
                if vlan.get("ip"):
                    if not results.get("interfaces", None):
                        results["interfaces"] = []
                    results["interfaces"].append(
                        {
                            "routed_vlan": {
                                "ipv4": {"addresses": {"ip": vlan.get("ip")}}
                            },
                            "config": {"type": "IF_ROUTED_VLAN"},
                            "name": "VLAN" + vlan.get("vlan-id"),
                            "vlan-id": vlan.get("vlan-id"),
                        }
                    )
                # Add untagged interfaces
                for interface in vlan.get("members", {}).get("untagged", []):
                    if not interface in interfaces:
                        interfaces[interface] = {
                            "name": interface,
                            "config": {"type": "IF_ETHERNET"},
                            "switched-vlan": {"config": {}},
                        }
                    if not interfaces[interface].get("switched-vlan"):
                        interfaces[interface]["switched-vlan"] = {"config": {}}
                    interfaces[interface]["switched-vlan"]["config"]["access-vlan"] = (
                        vlan.get("vlan-id")
                    )
                # Add tagged interfaces
                for interface in vlan.get("members", {}).get("tagged", []):
                    if not interface in interfaces:
                        interfaces[interface] = {
                            "name": interface,
                            "config": {"type": "IF_ETHERNET"},
                            "switched-vlan": {"config": {}},
                        }
                    if not interfaces[interface].get("switched-vlan"):
                        interfaces[interface]["switched-vlan"] = {"config": {}}
                    if not interfaces[interface]["switched-vlan"]["config"].get(
                        "trunk-vlans"
                    ):
                        interfaces[interface]["switched-vlan"]["config"][
                            "trunk-vlans"
                        ] = []
                    interfaces[interface]["switched-vlan"]["config"][
                        "trunk-vlans"
                    ].append(vlan.get("vlan-id"))
            # Set interface-modes
            for interface in interfaces.values():
                if not "switched-vlan" in interface:
                    continue
                if not "trunk-vlans" in interface.get("switched-vlan", {}).get(
                    "config", {}
                ):
                    interface["switched-vlan"]["config"]["interface-mode"] = "ACCESS"
                else:
                    interface["switched-vlan"]["config"]["interface-mode"] = "TRUNK"
            p = re.compile(r"(\d+)")
            results["interfaces"] = sorted(
                [v for k, v in interfaces.items()],
                key=lambda x: extract_num(x["name"], p, 999),
            )
            with open(BACKUP_DIR.joinpath(f"{self.host}.oc"), "w") as f:
                f.write(json.dumps(results))
            return results
        except Exception as e:
            print(e)
            pass

    def send_configlet(
        self, commands: str | list[str], dryrun=True, save_config=True
    ) -> str:
        if not commands:
            commands = []
        res = self.conn.send_command("reload after 5", expect_string=".*")
        self.conn.write_channel("y\r\n")

        self.conn.send_config_set(commands)
        # check if able to reconnect
        self.conn.disconnect()

        try:
            self.conn.establish_connection()
            time.sleep(5)
            self.conn.write_channel("\r\n")
            self.conn.send_command("no reload")

            self.write_config()
            return self.get_config()
        except Exception as e:
            return {"result": {"type": "failure", "error": e}}

    def write_config(self):
        self.conn.send_command("write memory")

    def commit(self, save_config=True):
        raise NotImplementedError

    def rollback(self, name="startup-config") -> None:
        raise NotImplementedError

    def health_check(self) -> None:
        raise NotImplementedError


def extract_num(s, p, ret=0):
    search = p.search(s)
    if search:
        return int(search.groups()[0])
    else:
        return ret


###########################################################################################################
# netmiko
###########################################################################################################
def device_connection(
    hostname,
    user,
    password,
    port=22,
):
    conn_info = {
        "device_type": "hp_procurve",
        "host": hostname,
        "port": port,
        "username": user,
        "password": password,
        "secret": "",
        "fast_cli": True,
    }

    return ConnectHandler(**conn_info)


def backup(hostname, user, password, output):

    with device_connection(str(hostname), user, password) as net_connect:
        net_connect.enable()
        net_connect.config_mode()
        net_connect.send_command("ip ssh filetransfer")

    with SSHClient() as ssh:
        ssh.set_missing_host_key_policy(AutoAddPolicy)
        ssh.connect(
            hostname=hostname,
            username=user,
            password=password,
            allow_agent=False,
            look_for_keys=False,
        )
        with SCPClient(ssh.get_transport()) as scp:
            scp.get("cfg/running-config", output)
            print("Config backup succesfull")


def backup_safe(hostname, user, password, output):
    try:
        backup(hostname, user, password, output)
    except Exception as e:
        print(e)


###########################################################################################################
# ttp parse functions
###########################################################################################################
def match_stacked_range(data, rangechar, joinchar, stackchar):
    """
    data - string, e.g. '8,1/10-1/13,20'
    rangechar - e.g. '-' for above string
    joinchar - e.g.',' for above string
    stackchar - e.g. '/'
    returns - e.g. '8,10,11,12,13,20 string
    """
    result = []
    try:
        for item in data.split(joinchar):
            if rangechar in item:
                start, end = item.split(rangechar)
                if stackchar in start:
                    start_first, start_end = start.split(stackchar)
                    end_first, end_end = end.split(stackchar)
                    for i in range(int(start_end), int(end_end) + 1):
                        result.append("{}{}{}".format(start_first, stackchar, i))
                else:
                    text = re.sub("[^0-9]".format(rangechar), "", start)
                    numeric_filter_start = filter(str.isdigit, start)
                    number_start = "".join(numeric_filter_start)
                    numeric_filter_end = filter(str.isdigit, end)
                    number_end = "".join(numeric_filter_end)
                    for i in range(int(number_start), int(number_end) + 1):
                        result.append(str(i))
            else:
                result.append(item)
        data = joinchar.join(result)
        return data, None
    except:
        return data, None


def parse(source, destination):
    try:
        template = SCRIPT_DIR.joinpath("ttp_templates", "show_run.ttp")
        parser = ttp(data=source, template=str(template))
        parser.add_function(match_stacked_range, scope="match", name="stacked_unrange")
        parser.parse()
        results = parser.result()[0][0]
        for vlan in results.get("vlans", []):
            if vlan.get("ip"):
                if not results.get("interfaces", None):
                    results["interfaces"] = []
                results["interfaces"].append(
                    {
                        "routed_vlan": {"ipv4": {"addresses": {"ip": vlan.get("ip")}}},
                        "config": {"type": "IF_ROUTED_VLAN"},
                        "name": "VLAN" + vlan.get("vlan-id"),
                        "vlan-id": vlan.get("vlan-id"),
                    }
                )
        with open(destination, "w") as f:
            f.write(json.dumps(results))
        return results
    except Exception as e:
        print(e)
        pass
