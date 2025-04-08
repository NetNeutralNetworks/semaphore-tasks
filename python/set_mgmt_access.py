import itertools
import logging
import multiprocessing
import os
import pathlib
import sys
import time
from typing import Any

from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader, select_autoescape
from nc_helpers.librenms import LibreNMS
from nc_helpers.netbox import Netbox
from nc_mis.drivers.juniper.JUNOS import JUNOS

load_dotenv()

logger = logging.getLogger("nc-mis")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

MAX_WORKERS: int = int(os.environ.get("MAX_WORKERS", multiprocessing.cpu_count() * 4))
logger.info(f"Using {MAX_WORKERS} workers")

SCRIPT_DIR = pathlib.Path(__file__).parent
DEVICE_DONE_LIST = SCRIPT_DIR.joinpath("device_list.txt")

J2_ENV = Environment(
    loader=FileSystemLoader(SCRIPT_DIR.joinpath("templates")),
    autoescape=select_autoescape(),
)


def C_RED(text: str):
    return f"\33[31m{text}\33[0m"


def C_GREEN(text: str):
    return f"\33[32m{text}\33[0m"


def C_YELLOW(text: str):
    return f"\33[33m{text}\33[0m"


def C_BOLD(text: str):
    return f"\33[1m{text}\33[0m"


# def exec_pool(FUNCTION,LIST):
#     with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
#         results = executor.map(FUNCTION,LIST)
#     return results


def health_check(
    driver: JUNOS, *, ignore_license: bool = False, ignore_status_control: bool = False
):
    """Checks the device health before executing commands.

    Raises:
        ValueError: The device has bad sectors on disk.
        ValueError: Disk report cannot be found.
        ValueError: Device has active alarms.
    """

    # Get the model number. This is a basic check.
    hardware: str = driver.conn.send_command(
        'show chassis hardware | match "Routing Engine"',
        expect_string=".*@.*[>#%]",
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
        storage_check = driver.conn.send_command(
            "file show /var/log/storagecheck-fpc-all.log"
        )
        if "Bad" in storage_check:
            raise ValueError(
                f"Bad sectors found on device {driver.conn.host}:\n{storage_check}\n"
            )
        # If the command output isn't found, the script hasn't been run.
        if "error: could not resolve file" in storage_check:
            raise ValueError(
                f"Health check report not found on {driver.conn.host}. Is the cron job installed?"
            )

    # Check for active alarms/errors on the device before committing.
    chassis_alarms = driver.conn.send_command("show chassis alarms")
    if chassis_alarms != "No alarms currently active\n":
        raise ValueError(
            f"Device {driver.conn.host} has active alarms:\n{chassis_alarms}\n"
        )
    system_alarms = driver.conn.send_command("show system alarms")
    if system_alarms != "No alarms currently active\n":
        alarm_list = system_alarms.strip().split("\n")[2:]
        if ignore_license:
            alarm_list = [x for x in alarm_list if "license" not in x]
        if ignore_status_control:
            alarm_list = [
                x for x in alarm_list if "prefer-status-control-active" not in x
            ]

        if alarm_list:
            raise ValueError(
                f"Device {driver.conn.host} has active alarms:\n{system_alarms}\n"
            )

    return


def connect(DRIVER, device_ip, log_prefix="unknown"):
    try:
        device = DRIVER(
            ip=device_ip,
            username=os.environ.get("device_username", ""),
            password=os.environ.get("device_password", ""),
        )
        return device
    except:
        logger.info(
            C_RED(f"{log_prefix}: Management ip not found or failed to authenticate")
        )
        return


def commit(driver: JUNOS):
    try:
        # driver.conn.commit(confirm=True, confirm_delay=10)
        driver.conn.config_mode()
        if "configuration check succeeds" not in (
            test := driver.conn.send_command("commit check", read_timeout=240).split(
                "\n"
            )
        ):
            logger.error("Commit failed, invalid configuration:\n%s", test)
            driver.rollback()
            return

        driver.conn.send_command("commit confirmed 5", read_timeout=240)

        driver.conn.disconnect()
        time.sleep(1)
        # check if able to reconnect
        driver.conn.establish_connection()

        # driver.conn.commit()
        driver.conn.config_mode()
        driver.conn.send_command("commit", read_timeout=240)
    except:
        logger.exception("")


def send_configlet(
    driver: JUNOS,
    commands: list[str],
    *,
    dryrun: bool = True,
    save_config: bool = False,
):
    driver.conn.config_mode()
    # TODO check if candidate config is empty before start
    logger.debug(
        driver.conn.send_command(
            "load replace terminal",
            expect_string="[Type ^D at a new line to end input]\n",
        )
    )
    for i in itertools.batched(commands, n=20):
        driver.conn.write_channel("\n".join(i) + "\n")
        time.sleep(0.2)
        # driver.conn.read_channel()
    driver.conn.write_channel("\x04")
    # Adding a slight delay for the device to process the command
    time.sleep(1)
    driver.conn.send_command(
        "", expect_string=".*@.*#", read_timeout=10
    )  # force to wait for expected config prompt.
    diff = driver.conn.send_command("show | compare")

    if dryrun:
        driver.rollback()

    return diff


def push_change(
    lnms_device: dict[str, str],
    management_prefixes: list[dict[str, str]],
    dns: dict[str, Any],
    *,
    dryrun: bool = True,
):
    config_changed = False
    try:
        # lnms_device = lnms_devices.get(nb_device.get('display',''))
        # if not lnms_device:
        #     return
        # device_manufacturer = nb_device.get('device_type').get('manufacturer').get('slug')
        # device_role = nb_device.get('device_role').get('slug')
        device_os = lnms_device.get("os", "")
        device_ip = f"{os.environ.get('V6_PREFIX', '')}{lnms_device.get('ip')}"
        device_name = lnms_device.get("sysName", "")
        # devcie_name = nb_device.get('display')
        # logservers = nb_mgmt_prefixes #nb_device.get('config_context').get('logservers')
        # devcie_ip = nb_device.get('primary_ip').get('address').split('/')[0]

        log_prefix = f"{device_name}, {device_ip}, {device_os}"

        logger.info(log_prefix)

        diff = None
        if device_os == "junos":
            # if config["device_type"] in ["qfx5120", "ex9200"]:
            if any(x in lnms_device["hardware"].lower() for x in ["qfx", "ex9208"]):
                device_template = J2_ENV.get_template("re-protect-qfx.j2")
            elif any(x in lnms_device["hardware"].lower() for x in ["jnp48y8c-chas"]):
                device_template = J2_ENV.get_template("re-protect-qfx.j2")
            elif any(x in lnms_device["hardware"].lower() for x in ["ex4300"]):
                device_template = J2_ENV.get_template("re-protect-ex4300.j2")
            elif any(
                x in lnms_device["hardware"].lower()
                for x in ["ex", "juniper virtual chassis switch"]
            ):
                device_template = J2_ENV.get_template("re-protect-ex.j2")
            elif lnms_device["version"].lower().startswith("15."):
                device_template = J2_ENV.get_template("re-protect-ex.j2")
            elif lnms_device["version"].lower().startswith("12."):
                device_template = J2_ENV.get_template("re-protect-ex.j2")
            elif device_name.lower().startswith("kpleswok1"):
                device_template = J2_ENV.get_template("re-protect-ex.j2")
            else:
                logger.warning("Device %s template not found.", device_name)
                return

            dns_template = J2_ENV.get_template("system-dns.j2")

            rendered_config = ""
            rendered_config = (
                device_template.render(
                    {
                        "device_name": device_name,
                        "os_version": lnms_device["version"],
                        "name": "re-protect",
                        "management_prefixes": management_prefixes,
                    }
                )
                + "\n"
            )
            rendered_config += dns_template.render(
                {
                    "device_name": device_name,
                    "dns": dns,
                }
            )
            device = connect(JUNOS, device_ip, log_prefix)
            if not device:
                return {"status": "FAILED", "device": log_prefix}

            with device:
                try:
                    health_check(
                        device, ignore_license=True, ignore_status_control=True
                    )
                except ValueError as err:
                    logger.warning(
                        "Device %s isn't in a healthy state.\n%s", device_name, err
                    )
                    return {"status": "IGNORED", "device": log_prefix}
                diff = send_configlet(
                    device, rendered_config.split("\n"), dryrun=dryrun
                )

                if not diff:
                    device.rollback()
                    logger.info(C_YELLOW(f"{log_prefix}: Config changed and saved"))
                    return {"status": "CHANGED", "device": log_prefix}

                if diff:
                    config_changed = True
                    logger.info(diff)

                if dryrun is False and diff:
                    commit(device)
                    with DEVICE_DONE_LIST.open("+a", encoding="utf-8") as fh:
                        fh.write(f"{device_name}\n")

        else:
            if os.environ.get("DEBUG", False):
                logger.info(
                    f"{log_prefix}: No manufacturer set or device is not a switch"
                )
            return {"status": "IGNORED", "device": log_prefix}

        # finish up
        if config_changed:
            logger.info(C_YELLOW(f"{log_prefix}: Config changed and saved"))
            return {"status": "CHANGED", "device": log_prefix}

        else:
            logger.info(C_GREEN(f"{log_prefix}: No changes needed"))
            return {"status": "UNCHANGED", "device": log_prefix}

    except Exception as e:
        logger.info(
            C_RED(
                f"{e}\n\n{log_prefix}: General failure, please contact an engineer to look into the issue, in the mean time check if changes can be done by logging in localy."
            )
        )
        return {"status": "FAILED", "device": log_prefix}


def main() -> None:
    dryrun = False
    host_filter = "bsw"

    librenms = LibreNMS()
    netbox = Netbox()

    done_devices = []
    DEVICE_DONE_LIST.touch(exist_ok=True)
    with DEVICE_DONE_LIST.open("+r") as fh:
        done_devices = fh.read().split("\n")

    lnms_devices = librenms.get_all_devices()
    # filter only devices that are up
    lnms_devices = [
        d
        for d in lnms_devices
        if d.get("status") == 1
        and d.get("os") == "junos"
        and d.get("sysName", "").lower() not in done_devices
        and host_filter in d.get("sysName", "").lower()
    ]
    # lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
    # nb_devices = netbox.get_all_devices()
    nb_mgmt_prefixes: list[dict[str, str]] = (
        netbox._get_single("/api/extras/config-contexts/?name=management-prefixes")
        .get("results", [{}])[0]
        .get("data", {})
        .get("management-prefixes", [])
    )
    if not nb_mgmt_prefixes:
        logger.info("NOOP: No management prefixes found.")
        return
    nb_dns: list[dict[str, str]] = (
        netbox._get_single("/api/extras/config-contexts/?name=dns-servers")
        .get("results", [{}])[0]
        .get("data", {})
        .get("dns", [])
    )
    if not nb_dns:
        logger.info("NOOP: No DNS configuration found.")
        return
    push_changes_params = [(d, nb_mgmt_prefixes, nb_dns) for d in lnms_devices]

    for i in push_changes_params:
        push_change(*i, dryrun=dryrun)

    # with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    #     results = executor.map(push_change, push_changes_params)

    ############################
    # push changes
    ############################
    # results = list(results)

    # sorted_results = sorted(results, key=lambda d: d["status"])
    # logger.info("\n" + "\n".join([str(r) for r in sorted_results]))


if __name__ == "__main__":
    main()
