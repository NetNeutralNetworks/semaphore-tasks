#!/bin/python3
import json
import logging
import pathlib
import typing

import jinja2

from nc_mis import consts
from nc_mis.drivers.abstract import Driver
from nc_mis.helpers.logger import logger

logger = logging.getLogger("nc-mis")
DATA_DIR = consts.DATA_DIR
BACKUP_DIR = DATA_DIR.joinpath("backup")
BACKUP_DIR.mkdir(exist_ok=True)


class JUNOS(Driver):
    device_type = "juniper_junos"

    def get_config(self):
        output = self.conn.send_command(
            "show configuration| display json | no-more",
            read_timeout=10,
            cmd_verify=False,
        )
        # logger.info(output)
        return json.loads(output).get("configuration", "")

    def send_config(self, commands):
        pass

    def send_config_port_profile(self, config: dict) -> None:
        logger.info(config)
        j_config = self.parse_from_openconfig_port_profile(config)
        logger.info(j_config)

        self.conn.config_mode()
        self.conn.send_command(
            "load replace terminal",
            expect_string="[Type ^D at a new line to end input]",
        )
        self.conn.write_channel(j_config + "\n\x04")

        logger.info(self.conn.send_command("show | compare"))
        self.commit()

    def send_configlet(self, commands:list, dryrun=True, save_config=True):
        self.conn.config_mode()
        #TODO check if candidate config is empty before start
        self.conn.send_command('load set terminal', expect_string="[Type ^D at a new line to end input]")
        self.conn.write_channel('\n'.join(commands)+'\n\x04')
        self.conn.send_command('',expect_string=".*@.*#") # force to wait for expected config prompt.
        logger.info(self.conn.send_command('show | compare'))

    def rollback(self, name: str | None = None):

        cmd = "rollback"
        if name and (name.isdigit() or name == "rescue"):
            cmd = f"{cmd} {name}"
        elif name is not None:
            raise ValueError("The value of name must be a number or 'rescue'.")
        logger.info(self.conn.send_command(cmd))

    def commit(self):
        try:
            # self.conn.commit(confirm=True, confirm_delay=10)
            self.conn.send_command("commit confirmed 10")

            self.conn.disconnect()
            # check if able to reconnect
            self.conn.establish_connection()

            # self.conn.commit()
            self.conn.send_command("commit")
        except:
            logger.exception("")

    def health_check(self):
        """Checks the device health before executing commands.

        Raises:
            ValueError: The device has bad sectors on disk.
            ValueError: Disk report cannot be found.
            ValueError: Device has active alarms.
        """

        # Get the model number. This is a basic check.
        hardware: str = self.conn.send_command(
            'show chassis hardware | match "Routing Engine"'
        )

        # NAND issue affecting EX (and some SRX) devices
        nand_affected_devices = [
            "EX2200",
            "EX3200",
            "EX3300",
            "EX4200",
            "EX4500",
            "EX8200",
        ]
        nand_affected = False
        for i in nand_affected_devices:
            if i in hardware:
                nand_affected = True
                break
        if nand_affected:
            # This report is the output of the nand_mediack -C command run daily.
            # Healthy devices show:
            #   Media check on da0 on ex platforms
            # Unhealthy devices show:
            #   Media check on da0 on ex platforms
            #       Zone 05 Block 0340 Addr 155400 : Bad read
            storage_check = self.conn.send_command(
                "file show /var/log/storagecheck-fpc-all.log"
            )
            if "Bad" in storage_check:
                raise ValueError(
                    f"Bad sectors found on device {self.conn.host}:\n{storage_check}\n"
                )
            # If the command output isn't found, the script hasn't been run.
            if "error: could not resolve file" in storage_check:
                raise ValueError(
                    f"Health check report not found on {self.conn.host}. Is the cron job installed?"
                )

        # Check for active alarms/errors on the device before committing.
        chassis_alarms = self.conn.send_command("show chassis alarms")
        if chassis_alarms != "No alarms currently active\n":
            raise ValueError(
                f"Device {self.conn.host} has active alarms:\n{chassis_alarms}\n"
            )
        system_alarms = self.conn.send_command("show system alarms")
        if system_alarms != "No alarms currently active\n":
            raise ValueError(
                f"Device {self.conn.host} has active alarms:\n{system_alarms}\n"
            )

        return

    def write_config(self):
        """
        docstring
        """
        return NotImplemented

    def get_vc_members(self) -> tuple:
        """
        gets members of VC en return a tuple of
        int of master fpc, int of backup fpc (none when there is no backup), list of integers fpc members
        """
        master, backup, members = None, None, []
        virtual_chassis = self.conn.send_command(
            "show virtual-chassis | display json",
            read_timeout=20,
            expect_string=".*@.*>",
        )
        virtual_chassis_json = json.loads(virtual_chassis)
        logger.debug(virtual_chassis_json)

        for member in virtual_chassis_json["virtual-chassis-information"][0][
            "member-list"
        ][0]["member"]:
            member_role = member["member-role"][0]["data"]
            member_id = int(member["member-id"][0]["data"])
            if "Master" in member_role:
                master = member_id
            elif "Backup" in member_role:
                backup = member_id
            members.append(member_id)

        return master, backup, members

    def parse_from_openconfig_port_profile(self, config: dict) -> str:
        SCRIPT_DIR = pathlib.Path(__file__).parent.joinpath("templates")

        environment = jinja2.Environment(loader=jinja2.FileSystemLoader(SCRIPT_DIR))
        template = environment.get_template("interface.j2")

        return template.render(interface=config)

    def parse_to_openconfig(
        self, config: str | dict = None, file=None
    ) -> dict[str, typing.Any]:
        """
        docstring
        """
        if config:
            config = config
        elif file:
            config = json.load(f)
        else:
            path = BACKUP_DIR.joinpath(f"{self.host}.cfg")
            with open(path, "r") as f:
                config = json.load(f)
        # LOG SERVERS
        junos_log_servers = config["system"].get("syslog", {}).get("host", [])
        oc_log_servers = {}
        for server in junos_log_servers:
            oc_log_servers.update(
                {server["name"]: {"config": {"host": server["name"]}}}
            )
        # SNMP COMMUNITIES
        junos_snmp_com = config.get("snmp", {}).get("community", [])
        oc_snmp_com = {}
        for community in junos_snmp_com:
            oc_snmp_com.update({community["name"]: {"config": {}}})
        # logger.info(oc_log_servers)
        # logger.info(oc_snmp_com)

        # Vlans
        oc_vlans = []
        for vlan in config.get("vlans", {}).get("vlan", []):
            oc_vlans.append(
                {
                    "config": {
                        "name": vlan.get("name", ""),
                        "description": vlan.get("description", ""),
                    },
                    "vlan-id": vlan.get("vlan-id"),
                }
            )

        # Interfaces
        junos_interfaces = config.get("interfaces", {}).get("interface", [])
        oc_interfaces = []
        for interface in junos_interfaces:
            if "xe" in interface["name"] or "et" in interface["name"]:
                type = "IF_ETHERNET"
            elif "ae" in interface["name"]:
                type = "IF_AGGREGATE"
            elif "em" in interface["name"]:
                type = "IF_MGMT"
            else:
                type = "IF_UNKNOWN"
            vlans = (
                interface.get("unit", [{}])[0]
                .get("family", {})
                .get("ethernet-switching", {})
                .get("vlan", {})
                .get("members", [])
            )
            temp = []
            for vlan in vlans:
                vlan_lookup = [
                    x["vlan-id"]
                    for x in oc_vlans
                    if x.get("config", {}).get("name", "") == vlan
                ]
                if len(vlan_lookup) < 1:
                    temp.append(vlan)
                    oc_vlans.append({"config": {}, "vlan-id": vlan})
                else:
                    temp.append(vlan_lookup[0])
            ipv4s = (
                interface.get("unit", [{}])[0]
                .get("family", {})
                .get("inet", {})
                .get("address", [])
            )
            oc_ips = {}
            for ip in ipv4s:
                oc_ips[ip.get("name")] = {"ip": ip.get("name")}
            oc_interfaces.append(
                {
                    "config": {"name": interface["name"], "type": type},
                    "ethernet": {
                        "config": {
                            "aggregate-id": interface.get("ether-options", {})
                            .get("ieee-802.3ad", {})
                            .get("bundle")
                        }
                    },
                    "switched-vlan": {"config": {"trunk-vlans": temp}},
                    "routed-vlan": {
                        "ipv4": {
                            "addresses": {
                                "address": oc_ips,
                            },
                        },
                    },
                    "name": interface["name"],
                }
            )

        oc = {
            "system": {"config": {"hostname": config["system"].get("host-name")}},
            "logging": {"remote-servers": {"remote-server": oc_log_servers}},
            "snmp": {
                "communities": oc_snmp_com,
                "contact": {"location": config.get("snmp", {}).get("location", "")},
            },
            "interfaces": oc_interfaces,
            "vlans": oc_vlans,
        }

        # logger.info(oc)
        with open(BACKUP_DIR.joinpath(f"{self.host}.oc"), "w") as f:
            f.write(json.dumps(oc))
        return oc

    def backup_config(self) -> None:
        """
        docstring
        """
        config = self.get_config()
        with open(BACKUP_DIR.joinpath(f"{self.conn.host}.cfg"), "w") as file:
            json.dump(config, file)
        # return NotImplemented

    def send_command_as_root(
        self, command: str, password: str, shell="sh", timeout=10
    ) -> None:
        """
        drops to shell as root to sh and performs a command as root
        """
        try:
            self.conn.send_command(f"start shell user root", expect_string="Password:")
            self.conn.send_command(
                f"{password}", expect_string=".*:[0-9]%", cmd_verify=False
            )
            if shell == "sh":
                # Start Bourne-style shell (really ash)
                self.conn.send_command("sh", expect_string="# ")
                logger.debug(self.conn.send_command(command, read_timeout=timeout))
                # exits Bourne-style shell
                self.conn.send_command("exit", expect_string=".*:[0-9]%")
            elif shell == "csh":
                logger.debug(self.conn.send_command(command, read_timeout=timeout))
            # go back to CLI before ending this definition
            self.conn.send_command("exit", expect_string=".*@.*>")
        except Exception as e:
            print(e)
        return

    def send_command_as_root_fpc(
        self, command: str, password: str, fpc: str, shell="sh", timeout=10
    ) -> None:
        """
        drops to shell as root to sh and performs a command as root in specific fpc shell
        """
        try:
            self.conn.send_command(f"start shell user root", expect_string="Password:")
            self.conn.send_command(
                f"{password}", expect_string=".*:[0-9]%", cmd_verify=False
            )
            if shell == "sh":
                # enter FPC
                self.conn.send_command(
                    f"rlogin -Ji fpc{fpc}", expect_string=".*:[0-9]%"
                )
                # Start Bourne-style shell (really ash)
                self.conn.send_command("sh", expect_string="# ")
                logger.debug(self.conn.send_command(command, read_timeout=timeout))
                # exits FPC shell
                self.conn.send_command("exit", expect_string=".*:[0-9]%")
                # exits Bourne-style shell
                self.conn.send_command("exit", expect_string=".*:[0-9]%")
            elif shell == "csh":
                # enter FPC
                self.conn.send_command(
                    f"rlogin -Ji fpc{fpc}", expect_string=".*:[0-9]%"
                )
                logger.debug(self.conn.send_command(command, read_timeout=timeout))
                # exits FPC shell
                self.conn.send_command("exit", expect_string=".*:[0-9]%")
            # go back to CLI before ending this definition
            self.conn.send_command("exit", expect_string=".*@.*>")
        except Exception as e:
            print(e)
        return
