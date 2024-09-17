"""
Defines the interfaces used by nc-mis to talk to external systems. This allows for a plug-in system.
"""

import abc
import logging
import pathlib
import typing

import netmiko


class Platform:
    ARUBAOS_CX = "arubaos-cx"
    HP_PROCURVE = "hp_procurve"
    IOS = "cisco_ios"
    JUNOS = "junos"
    FS = "fs-switch"


class Driver(metaclass=abc.ABCMeta):
    """
    Interface declaring the functions needed to manipulate devices.
    https://realpython.com/python-interface/#using-abstract-method-declaration
    """

    conn: netmiko.BaseConnection
    logger: logging.Logger
    device_type = "unknown_device_type"

    def __init__(self, ip: str, username: str, password: str):
        self.conn = netmiko.ConnectHandler(
            device_type=self.device_type,
            ip=ip,
            username=username,
            password=password,
            auto_connect=False,
        )
        self.host = ip

    def __enter__(self):
        self.conn.establish_connection()
        return self

    def __exit__(self, *args, **kwargs):
        self.conn.disconnect()

    @abc.abstractmethod
    def get_config(self) -> str:
        """Retrieves the active/running configuration from a device.

        Returns:
            str: The running configuration if available.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def backup_config(self) -> None:
        """Saves the running config to ${const.DATA_DIR}/config/{ip}.cfg

        Returns:
            None

        Raises:
            Exception: If failed to backup device
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send_config(self, commands: str | list[str]) -> str:
        """Sends configuration statements to the device
            This function only sends the commands. It doesn't commit or save the configuration.
            Depending on the device, the configuration changes may become active immediately.

        Args:
            commands (str | list[str]): String or list of strings to send to the device.
            These must be configuration statements.


        Raises:
            NotImplementedError: _description_

        Returns:
            str: Returns the diff of the changes.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send_config_port_profile(self, commands: str | list[str]) -> str:
        """Sends configuration statements for a specific port to the device
            This function only sends the commands. It doesn't commit or save the configuration.
            Depending on the device, the configuration changes may become active immediately.

        Args:
            commands (str | list[str]): String or list of strings to send to the device.
            These must be configuration statements.


        Raises:
            NotImplementedError: _description_

        Returns:
            str: Returns the diff of the changes.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def parse_to_openconfig(
        self,
        config: str | dict[str, typing.Any] | None = None,
        file: pathlib.Path | None = None,
    ) -> dict[str, typing.Any]:
        """Parse the device configuration to OpenConfig if needed.

        Args:
            config (str | dict): The configuration to convert to OpenConfig

        Returns:
            dict[str, typing.Any]: The OpenConfig datas structure.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def send_configlet(
        self, commands: str | list[str], dryrun: bool = True, save_config: bool = True
    ) -> str:
        """Sends configuration statements to the device. This function has more functionality
        built-in compared to send_config. It will automatically roll back the changes if
        connectivity is lost.

        By default, no changes are performed and only a dry-run is executed.

        If changes are successful, these are committed and saved.

        Args:
            commands (str | list[str]): String or list of strings to send to the device.
            These must be configuration statements.
            dryrun (bool, optional): Whether the configuration shouldn't be applied. Defaults to True.
            save_config (bool, optional): Whether the configuration should be saved. Defaults to True.

        Returns:
            str: Returns the diff of the changes.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def write_config(self):
        raise NotImplementedError

    @abc.abstractmethod
    def commit(self, save_config=True):
        raise NotImplementedError

    @abc.abstractmethod
    def rollback(self, name: str | None = None) -> None:
        """Rolls the configuration back to the previous working state.

        Args:
            name (str, optional): _description_. Defaults to None.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def health_check(self) -> None:
        """Performs device health checks.

        Raises:
            ValueError: Device is unhealthy
        """
        raise NotImplementedError
