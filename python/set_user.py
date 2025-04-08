import yaml
import argparse
import os
import sys
import re
from time import sleep
from nc_mis.helpers.netbox import Netbox
from nc_mis.helpers.librenms import LibreNMS

import ipaddress

from nc_mis.drivers.hp.procurve import PROCURVE
from nc_mis.drivers.aruba.aos.AOS import AOS
from nc_mis.drivers.fs.fs import FS

import concurrent.futures
import multiprocessing
import logging

librenms = LibreNMS()
netbox = Netbox()

lnms_devices = librenms.get_all_devices()
# filter only devices that are up
#lnms_devices = [d for d in lnms_devices if d.get('status') == 1]
lnms_devices_map = {d['sysName'].split('.')[0]:d for d in lnms_devices}
#nb_devices = netbox.get_all_devices()
nb_snmp_config = netbox._get_single("/api/extras/config-contexts/?name=snmp").get('results',[{}])[0].get('data',{}).get('snmp',[])


#! /usr/bin/env python3

"""
Module is able to create users, reset passwords and delete users from Cisco IOS(-XE) and Juniper
devices.
"""

import hashlib
import json
import logging
import os
import pathlib
import re
import time
from typing import List, Optional

import deepdiff
import jinja2
import mis_crypt
import netmiko
from nornir import InitNornir
from nornir.core.exceptions import ConnectionNotOpen
from nornir.core.filter import F
from nornir.core.task import Result, Task
from nornir_napalm.plugins.tasks import (
    napalm_cli,
    napalm_configure,
    napalm_confirm_commit,
    napalm_get,
    napalm_ping,
)
from nornir_netmiko.tasks import (
    netmiko_commit,
    netmiko_save_config,
    netmiko_send_command,
    netmiko_send_config,
)
from nornir_utils.plugins.functions import print_result

SCRIPTDIR = pathlib.Path(__file__).parent

# import hashlib

# Split the commit output on prompt
# splits on:
# #

# {master:0}
# user@hostname>

# user@hostname>
COMMIT_SPLIT = re.compile(r"(\n\#|\n\{\S+:\d+\}\n\S+?>|\n\S+?>)")

J2_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(SCRIPTDIR.joinpath("templates")),
    extensions=["jinja2.ext.do"],
)


def get_max_hash_alg_supported(vendor: str, version: str) -> Optional[str]:
    """
    Get the strongest supported cryptographic hashing algorithm for the vendor
    and OS combination.
    """
    if vendor == "Juniper":
        return "6"  # SHA512
    elif vendor == "Cisco":
        if "12.2" in version:
            return "1"  # MD5
        # IOL
        if "15.7" in version:
            return "9"  # Scrypt
        if "16." in version:
            return "9"
        if "03.07.00.E" in version:
            return "9"
        else:
            return "9"

    return None


def wait_for_commit(task, retry_count: int = 30, retry_interval: int = 10):
    """
    Waits for the commit to finish. Polls the device every 10 seconds by
    default for 5 minutes.
    """

    retries = 0
    commit_confirm_done = False
    # While loop that runs when 'retry_interval' * 'retry_count' seconds have
    # passed or the commit has succeeded.
    while not commit_confirm_done and retries < retry_count:
        commit_check = task.run(
            task=netmiko_send_command,
            command_string="show system commit server | display json",
            severity_level=logging.DEBUG,
        )
        # Remove the prompts that appear after running the above command.
        result_split = COMMIT_SPLIT.split(commit_check.result, maxsplit=1)
        try:
            result_obj = json.loads(result_split[0])
            if (
                result_obj["commit-server-information"][0]["server-status"][0]["data"]
                == "not running"
            ):
                commit_confirm_done = True
            else:
                retries = retries + 1
                print(task.host, "not yet committed", retries)
                time.sleep(retry_interval)
        except json.JSONDecodeError:
            retries = retries + 1
            print(task.host, "commit JSON decode error", retries)
            if retries >= 3:
                break
            time.sleep(retry_interval)

    if retries >= retry_count:
        res = (
            f"Commit duration exceeds maximum duration of {retry_count * retry_interval} seconds",
        )
        return Result(
            host=task.host,
            result=res,
            changed=True,
            failed=True,
        )
    else:
        return Result(
            host=task.host,
            result=f"Commit finished in {retries * retry_interval} seconds",
            changed=True,
            failed=False,
        )


def validate_account(task: Task, username, password):
    """
    Validate that new credentials work.
    """
    # Get the current netmiko connection
    conn_name = "netmiko"

    # Close the existing connection.
    try:
        task.host.close_connection(conn_name)
    except ConnectionNotOpen:
        # with LOCK:
        print("connection not open")

    print("Opening connection")
    # Open a new connection to the device with the new credentials.
    task.host.open_connection(
        conn_name,
        configuration=task.nornir.config,
        username=username,
        password=password,
    )
    print("Connection opened, closing")
    # Close the connection if succeeded.
    task.host.close_connection(conn_name)
    print("Connection closed")


def delete_user_cisco(task: Task, username):
    """
    Validate that new credentials work.
    """

    # Close the existing connection.
    conn: netmiko.BaseConnection = task.host.get_connection(
        "netmiko", task.nornir.config
    )
    output: str = conn.config_mode()
    output += conn.send_command(f"no username {username}", expect_string=r"confirm")
    output += conn.send_command("y\n")
    output += conn.exit_config_mode()

    return output


def set_user(
    task: Task, vendor: str, version: str, username: str, password: str, validate: bool
):
    """
    Create or update the user account/hash.
    """

    hash_alg = get_max_hash_alg_supported(vendor, version)
    hash_str = mis_crypt.generate_hash(hash_alg, password)

    cmds = []

    if "ios" in task.host.groups:
        # $1 hashes are called type 5 in Cisco
        if hash_alg == "1":
            hash_alg = "5"
        cmds = [f"username {username} privilege 15 secret {hash_alg} {hash_str}"]

    if "junos" in task.host.groups:
        if username == "root":
            cmds = [f'set system root-authentication encrypted-password "{hash_str}"']
        else:
            cmds = [
                f'set system login user {username} class super-user authentication encrypted-password "{hash_str}"'
            ]

    if not cmds:
        return

    try:
        # delete user in cisco.
        if "ios" in task.host.groups:
            del_user_task = task.run(task=delete_user_cisco, username=username)
    except Exception as err:
        print_result(err)

    # Create/update the user account by sending the commands.
    add_user_task = task.run(
        task=netmiko_send_config,
        config_commands=cmds,
    )
    # If the OS is JunOS, perform a commit confirmed.
    if "junos" in task.host.groups:
        task.run(
            task=netmiko_commit,
            confirm=True,
            confirm_delay=5,
            delay_factor=4,
            read_timeout=300,
        )

        # Commits can take a long time, wait for the commit by polling the device.
        # task.run(task=wait_for_commit)

    # Validate that a login is possible with the newly updated account.
    if validate is True:
        validate_config = task.run(
            task=validate_account,
            username=username,
            password=password,
        )

        # Save/commit the configuration if login succeeded.
        if "ios" in task.host.groups and validate_config.failed is False:
            task.run(task=netmiko_save_config)
        elif "junos" in task.host.groups and validate_config.failed is False:
            task.run(task=netmiko_commit, delay_factor=4, read_timeout=300)
            # task.run(task=wait_for_commit)
    else:
        # Save/commit the configuration if user shouldn't be validated.
        if "ios" in task.host.groups:
            task.run(task=netmiko_save_config)
        elif "junos" in task.host.groups:
            task.run(task=netmiko_commit, delay_factor=4, read_timeout=300)
            # task.run(task=wait_for_commit)

    return Result(
        host=task.host,
        result=add_user_task.result,
        changed=True,
        failed=add_user_task.failed,
    )


def delete_users(task: Task, usernames: List[str]):
    """
    Delete user accounts.
    """

    for username in usernames:
        # Construct the command per OS.
        if "ios" in task.host.groups:
            cmds = f"no username {username}"
            # Delete the user accounts by sending the commands.
            net_connect = task.host.get_connection("netmiko", task.nornir.config)
            output = net_connect.config_mode()
            output += net_connect.send_command(cmds, expect_string=r"confirm")
            output += net_connect.send_command("\n", expect_string=r"#")
            output += net_connect.exit_config_mode()
            # delete_users_task = task.run(
            #     task=netmiko_send_config,
            #     config_commands=cmds,
            #     expect_string="confirm"
            # )
            # confirm_deletion = task.run(
            #     task=netmiko_send_config,
            #     config_commands=["y"],
            # )

        elif "junos" in task.host.groups:
            if username == "root":
                continue
            else:
                cmds = [f"delete system login user {username}"]
                # Delete the user accounts by sending the commands.
                task.run(
                    task=netmiko_send_config,
                    config_commands=cmds,
                )

    # If the OS is JunOS, perform a commit confirmed.
    if "junos" in task.host.groups:
        task.run(
            task=netmiko_commit,
            confirm=True,
            confirm_delay=5,
            delay_factor=4,
            read_timeout=300,
        )

    # Save/commit the configuration if login succeeded.
    if "ios" in task.host.groups:
        task.run(task=netmiko_save_config)
    elif "junos" in task.host.groups:
        task.run(task=netmiko_commit, delay_factor=4, read_timeout=300)
        # task.run(task=wait_for_commit)

    # return Result(
    #     host=task.host,
    #     result=delete_users_task.result,
    #     changed=True,
    #     failed=delete_users_task.failed,
    # )


def update_user(
    task: Task,
    vendor: str,
    version: str,
    # current hash
    current_hash: str,
    username: str,
    password: str,
    validate: bool,
):
    """
    Validates that the current hash meets the minimum specs and is correct.
    Updates the user hash by calling 'set_user' if needed.
    """
    # Desired hash algorithm used for the device and OS version combination.
    d_alg = get_max_hash_alg_supported(vendor, version)
    # Current hash algorithm, current salt and (discarded) password hash.
    c_alg, c_salt, _ = mis_crypt.parse_hash_components(current_hash)

    # Calculate with the desired password and current salt, the password hash.
    calc_full_hash: Optional[str]
    if c_alg == d_alg and c_salt:
        calc_full_hash = mis_crypt.generate_hash(c_alg, password, c_salt)

        # If the hash calculated from the desired password and salt is the same
        # as the current hash, no action is performed.
        if calc_full_hash == current_hash:
            # This is good
            return Result(host=task.host, changed=False)

    # Hash doesn't meet the spec/is wrong. Update the user account.
    set_user(task, vendor, version, username, password, validate)


def set_tacacs(task: Task):
    """
    Create or update the TACACS authentication servers.
    """

    # hash_alg = get_max_hash_alg_supported(vendor, version)
    # hash_str = mis_crypt.(hash_alg, password)

    servers = task.host["tacacs"]

    # cmds = []

    if "ios" in task.host.groups:
        # # $1 hashes are called type 5 in Cisco
        # if hash_alg == "1":
        #     hash_alg = "5"
        # cmds = [f"username {username} privilege 15 secret {hash_alg} {hash_str}"]
        pass

    if "junos" in task.host.groups:
        tac_conf = task.run(
            task=napalm_cli,
            commands=["show configuration system tacplus-server | display set"],
        )
        tac_res = tac_conf.result[
            "show configuration system tacplus-server | display set"
        ]
        mgmt_ip_re = re.search(
            r"set system tacplus-server \S+ source-address (\S+)", tac_res
        )
        mgmt_ip = None
        if mgmt_ip_re:
            mgmt_ip = mgmt_ip_re[1]
        routing_instance_re = re.search(
            r"set system tacplus-server \S+ routing-instance (\S+)", tac_res
        )
        routing_instance = None
        if routing_instance_re:
            routing_instance = routing_instance_re[1]

        template = J2_ENV.get_template("tacacs.j2")
        render = template.render(servers=servers, mgmt_ip=mgmt_ip, routing_instance=routing_instance)

        result = task.run(napalm_configure, configuration=render, revert_in=180)

    # Validate that a login is possible with the newly updated account.
    validate_config = task.run(
        task=validate_account,
        username=task.host.username,
        password=task.host.password,
    )

    if validate_config.failed:
        return Result(
            host=task.host,
            result=validate_config.result,
            changed=True,
            failed=validate_config.failed,
        )

    # Save/commit the configuration if login succeeded.
    if "ios" in task.host.groups and validate_config.failed is False:
        task.run(task=netmiko_save_config)
    elif "junos" in task.host.groups and validate_config.failed is False:
        task.run(task=napalm_confirm_commit)
        # task.run(task=wait_for_commit)

    time.sleep(10)
    ping = task.run(task=napalm_ping, dest=task.host.hostname)

    if ping.failed:
        return Result(
            host=task.host,
            result=ping.result,
            changed=True,
            failed=ping.failed,
        )

    return Result(
        host=task.host,
        result=result.diff,
        changed=result.changed,
        failed=result.failed,
    )


def manage_users(task, facts, vendor, version, existing_users):
    for account in task.host["users"]["add"]:
        username = account["username"]
        password = account["password"]
        validate = account.get("validate", True)

        # Create missing users
        if username not in existing_users:
            res = task.run(
                task=set_user,
                vendor=vendor,
                version=version,
                username=username,
                password=password,
                validate=validate,
            )
            # with LOCK:
            print_result(res)
        # Update users if needed.
        else:
            current_hash = facts.result["users"][username]["password"]
            res = task.run(
                task=update_user,
                vendor=vendor,
                version=version,
                current_hash=current_hash,
                username=username,
                password=password,
                validate=validate,
            )
            # with LOCK:
            print_result(res)

    added_list = [x["username"] for x in task.host["users"]["add"]]

    # Delete users
    delete_list = []
    task_del_list = task.host["users"]["del"]
    for username in task_del_list:
        if username in added_list:
            print(f"Will not delete user '{username}' as it's in the 'add users' list.")
            continue
        if not username in existing_users:
            print(
                f"Will not delete user '{username}' as it doesn't exist on the device."
            )
            continue
        delete_list.append(username)

    if delete_list:
        # with LOCK:
        print_result(task.run(task=delete_users, usernames=delete_list))


def manage_device(task: Task):
    """Manages user accouns on devices. Can add, update or delete users on a system."""

    # Retrieve users and system information (such as OS version)
    facts = task.run(
        task=napalm_get,
        getters=["facts", "users"],
        severity_level=logging.DEBUG,
    )
    vendor = facts.result["facts"]["vendor"]
    version = facts.result["facts"]["os_version"]
    existing_users = facts.result["users"].keys()

    manage_users(task, facts, vendor, version, existing_users)

    set_tacacs(task)

    manage_dot1x(task, vendor, version)


def get_dot1x(task: Task):
    dot1x_config_str = task.run(
        task=netmiko_send_command,
        command_string="show configuration access | display json",
        severity_level=logging.DEBUG,
    )

    dot1x_config = json.loads(dot1x_config_str.result)["configuration"][0].get(
        "access", [{}]
    )[0]

    return dot1x_config


def update_dot1x_check(task: Task, config) -> bool:

    if not config.get("radius-server"):
        return False

    if len(task.host["dot1x"]["servers"]) != len(config.get("radius-server", [])):
        return True
    inv_servers = [x["ip"] for x in task.host["dot1x"]["servers"]]
    dev_servers = [x["name"]["data"] for x in config["radius-server"]]
    for i in inv_servers:
        if i not in dev_servers:
            return True
    for i in task.host["dot1x"]["servers"]:
        dev_server = None
        for j in config["radius-server"]:
            if j["name"]["data"] == i["ip"]:
                dev_server = j
                break

        if mis_crypt.junos_decrypt(dev_server["secret"][0]["data"]) != i["secret"]:
            return True
    ###################
    ###################
    ### CHANGE BACK ###
    return True


def array_on_duplicate_keys(ordered_pairs):
    """Convert duplicate keys to arrays."""
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            if type(d[k]) is list:
                if isinstance(v, list):
                    d[k].extend(v)
                else:
                    d[k].append(v)
            else:
                d[k] = [d[k], v]
        else:
            d[k] = v
    return d


def dot1x_interface_state(task: Task):
    table_str = task.run(
        netmiko_send_command,
        command_string="show ethernet-switching interfaces detail | display json",
        severity_level=logging.DEBUG,
    )
    table = json.loads(table_str.result, object_pairs_hook=array_on_duplicate_keys)[
        "switching-interface-information"
    ][0]["interface"]
    table = [
        x
        for x in table
        if x["interface-state"][0]["data"] != "down"
        and not x["interface-name"][0]["data"].startswith("ae")
    ]
    for row in table:
        # print(row)
        member_list = [
            x
            for x in row["interface-vlan-member-list"][0]["interface-vlan-member"]
            if x.get("interface-vlan-mac")
        ]

        row["interface-vlan-member-list"][0]["interface-vlan-member"] = member_list

    inf_dict = {}
    for row in table:
        vlan_dict = {}
        for vlan in row["interface-vlan-member-list"][0]["interface-vlan-member"]:
            macs = [x["data"] for x in vlan["interface-vlan-mac"]]
            vlan_dict[vlan["interface-vlan-member-tagid"][0]["data"]] = {
                "name": vlan["interface-vlan-name"][0]["data"],
                "macs": macs,
            }

        inf_dict[row["interface-name"][0]["data"]] = vlan_dict

    return inf_dict


def manage_dot1x(task: Task, vendor, version):
    if not task.host["dot1x"]:
        return

    if not version.startswith("15"):
        return

    config = get_dot1x(task)
    if not update_dot1x_check(task, config):
        return

    inf_state_pre = dot1x_interface_state(task)
    affected_interfaces = [
        k.split(".")[0]
        for k, v in inf_state_pre.items()
        if v.get("2717", {}).get("macs") or v.get("2722", {}).get("macs")
    ]

    # # TODO remove:
    # if affected_interfaces:
    #     return

    hostname = task.host.name
    hostname_hash = int(hashlib.sha256(hostname.encode()).hexdigest(), 16)
    print("###########################GBS##################")
    print(hostname)
    print(
        [
            v.get("2717", v.get("2722", {})).get("macs")
            for _, v in inf_state_pre.items()
            if v.get("2717", {}).get("macs") or v.get("2722", {}).get("macs")
        ]
    )

    test_inf = None
    for k, v in inf_state_pre.items():
        if test_inf:
            break
        for l, w in v.items():
            if w.get("macs"):
                test_inf = k
                break

    out_file = SCRIPTDIR.joinpath("output", f"{task.host.name}.pre.json")
    if not out_file.exists():
        out_file.write_text(json.dumps(inf_state_pre))

    source_address = (
        config["radius-server"][0].get("source-address", [{}])[0].get("data")
    )
    encrypted_dict = [
        {"ip": x["ip"], "secret": mis_crypt.junos_encrypt(x["secret"])}
        for x in task.host["dot1x"]["servers"]
    ]

    if not hostname_hash % 2:
        encrypted_dict.reverse()
    template = J2_ENV.get_template("dot1x-radius.j2")
    render = template.render(
        servers=encrypted_dict,
        source_address=source_address,
        # affected_interfaces=affected_interfaces,
        affected_interfaces=[],
    )
    print_result(task.run(napalm_configure, configuration=render, dry_run=True))
    print()
    conf_res = task.run(
        napalm_configure, configuration=render, commit_message="clearpass update"
    )

    # if affected_interfaces:
    #     cmds = []
    #     for inf in affected_interfaces:
    #         cmds.append(f"delete interfaces {inf} disable")
    #     print_result(
    #         task.run(
    #             netmiko_send_config,
    #             config_commands=cmds,
    #         )
    #     )
    #     task.run(netmiko_commit)

    # print_result(task.run(netmiko_send_command, command_string=f"clear dot1x interface {test_inf}"))
    if test_inf:
        affected_interfaces.append(test_inf)
    cmds = [f"clear dot1x interface {x}" for x in affected_interfaces]
    if cmds:
        print("######################################### SLEEPING #")
        print(cmds)

        for cmd in cmds:
            print_result(task.run(netmiko_send_command, command_string=cmd))

    print("######################################### SLEEPING #")
    time.sleep(60)
    inf_state_post = dot1x_interface_state(task)
    SCRIPTDIR.joinpath("output", f"{task.host.name}.post1.json").write_text(
        json.dumps(inf_state_post)
    )
    print("######################################### DIFF START")
    diff = deepdiff.DeepDiff(inf_state_pre, inf_state_post)
    changed = bool(diff)
    diff_result = Result(task.host, result=diff, diff=diff, changed=changed)
    print_result(diff_result)
    print("######################################### DIFF END #")

    return conf_res


def main():
    """
    Starts the main execution
    """
    config_file = pathlib.Path(__file__).parent.joinpath("config.yaml").resolve()
    nr = InitNornir(config_file=str(config_file))

    # Environment variables have precedence over configuration file
    username = os.getenv("NORNIR_USERNAME")
    password = os.getenv("NORNIR_PASSWORD")
    if username:
        nr.inventory.defaults.username = username
    if password:
        nr.inventory.defaults.password = password

    username = password = None

    nr = nr.filter(~F(groups__contains="ok") & F(groups__all=["junos", "rkc"]))

    results = nr.run(manage_device)

    print_result(results)
    print(f"Failed count: {len(results.failed_hosts)}")
    print(f"Failed hosts: {results.failed_hosts}")
    # pass


if __name__ == "__main__":
    main()
