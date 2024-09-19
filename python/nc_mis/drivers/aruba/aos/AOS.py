import json
import logging
import pathlib
import traceback
import urllib.parse
from datetime import datetime

import netmiko.hp
from ttp import ttp

#from nc_mis import consts
from nc_mis.drivers.abstract import Driver

logger = logging.getLogger("nc-mis")

# SCRIPT_DIR = pathlib.Path(__file__).parent
# DATA_DIR = consts.DATA_DIR
# BACKUP_DIR = DATA_DIR.joinpath("backup")
# BACKUP_DIR.mkdir(exist_ok=True)


class AOS(Driver):
    def __init__(self, ip: str, username: str, password: str) -> None:
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
        output = self.conn.send_command("show run")
        with open(
            BACKUP_DIR.joinpath(f"{self.conn.host}.cfg"), "w", encoding="utf-8"
        ) as file:
            file.write(output)

    def get_config(self):
        output = self.conn.send_command("show run json")
        json_string = output.split("\n", 1)[1]
        return json.loads(urllib.parse.unquote(json_string))

    def send_config(self, commands: list = None):
        if not commands:
            commands = []
        res = self.conn.send_command("checkpoint auto 1")
        if not "Success" in res:
            self.conn.send_command("checkpoint auto confirm")
            res = self.conn.send_command("checkpoint auto 1")
            if not "Success" in res:
                raise (res)

        self.conn.send_config_set(commands)
        # check if able to reconnect
        self.conn.disconnect()
        try:
            self.conn.establish_connection()
            self.conn.send_command("checkpoint auto confirm")
            return self.get_config(self.conn)
        except Exception as e:
            return {"result": {"type": "failure", "error": e}}

    def parse_to_openconfig(self, config=None, file=None):
        if config:
            config = config
        elif file:
            config = file
        else:
            config = BACKUP_DIR.joinpath(f"{self.host}.cfg")

        try:
            template = SCRIPT_DIR.joinpath("ttp_templates", "show_run.ttp")
            parser = ttp(
                data=config,
                template=str(template),
            )
            parser.add_function(
                match_stacked_range, scope="match", name="stacked_unrange"
            )
            parser.parse()

            results = parser.result()[0][0]
            with open(
                BACKUP_DIR.joinpath(f"{self.host}.oc"), "w", encoding="utf-8"
            ) as f:
                f.write(json.dumps(results))
            return results
        except Exception as e:
            traceback.print_stack()
            print(f"\n\nERROR: {e}\n\n")

    def send_configlet(self, commands: list = None, dryrun=True, save_config=True):
        if not commands:
            commands = []
        res = self.conn.send_command("checkpoint auto 1")
        if not "Success" in res:
            self.conn.send_command("checkpoint auto confirm")
            res = self.conn.send_command("checkpoint auto 1")
            if not "Success" in res:
                raise (res)

        commands.insert(0, "configure")
        commands.append("")
        config_changes = "\\n".join(commands)
        change_folder = "changes"
        pending_change_file = f"{change_folder}/pending_changes"
        finished_change_file = f"{change_folder}/change_{datetime.now().isoformat()}"
        shell_expect_string = ".*:.\$"
        try:
            if dryrun is False:
                self.write_config()
                logger.debug(
                    self.conn.send_command(
                        "start-shell", expect_string=shell_expect_string
                    )
                )
                logger.debug(
                    self.conn.send_command(
                        f"mkdir -p {change_folder}", expect_string=shell_expect_string
                    )
                )
                if (
                    self.conn.send_command(
                        f"ls {pending_change_file}", expect_string=shell_expect_string
                    )
                    == pending_change_file
                ):
                    return {
                        "result": {
                            "type": "failure",
                            "error": f"{pending_change_file} exists, change in progress or failed state, try again later or check for failure.",
                        }
                    }
                # put all changes in a change file on the device
                logger.debug(
                    self.conn.send_command(
                        f'printf "{config_changes}" > {pending_change_file}',
                        expect_string=shell_expect_string,
                    )
                )
                logger.debug(
                    self.conn.send_command(
                        f'vtysh -E -c "$(cat {pending_change_file})"',
                        expect_string=shell_expect_string,
                    )
                )
                self.conn.disconnect()
                # check if able to reconnect
                self.conn.establish_connection()

                changes = self.conn.send_command(
                    "checkpoint diff startup-config running-config"
                )

                self.commit(save_config=save_config)
                logger.debug(
                    self.conn.send_command(
                        "start-shell", expect_string=shell_expect_string
                    )
                )
                logger.debug(
                    self.conn.send_command(
                        f"mv {pending_change_file} {finished_change_file}",
                        expect_string=shell_expect_string,
                    )
                )
                logger.debug(self.conn.send_command("exit", expect_string=".*#"))

                return changes
            else:
                # -C does not do anything?
                # logger.debug(self.conn.send_command(f'printf "{config_changes}" > {finished_change_file}',expect_string=shell_expect_string))
                # logger.debug(self.conn.send_command(f'vtysh -C -c "$(cat {finished_change_file})"',expect_string=shell_expect_string))
                # logger.debug(self.conn.send_command(f'rm {finished_change_file}',expect_string=shell_expect_string))
                return config_changes

        except Exception as e:
            return {"result": {"type": "failure", "error": e}}

    def write_config(self):
        self.conn.send_command("copy running-config startup-config")

    def commit(self, save_config=True):
        self.conn.send_command("checkpoint auto confirm")
        if save_config:
            self.write_config()

    def rollback(self, name: str | None = None) -> None:
        # logger.info(self.conn.send_command('rollback'))
        if name is None:
            name = "startup-config"
        logger.debug(self.conn.send_command(f"checkpoint rollback {name}"))

    def health_check(self) -> None:
        # raise NotImplementedError("Health Check is not implemented for AOS, make it so!")
        NotImplemented


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
