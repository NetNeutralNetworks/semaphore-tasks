import json
import logging
import uuid

from nc_mis import consts
from nc_mis.helpers.netbox import Netbox

logger = logging.getLogger("nc-mis")
DATA_DIR = consts.DATA_DIR
BACKUP_DIR = DATA_DIR.joinpath("backup")
BACKUP_DIR.mkdir(exist_ok=True)


def load_port_profiles():

    netbox = Netbox()
    known_profiles = netbox._get("/api/extras/config-contexts/?name__isw=pp:")
    known_profiles = {x["name"][3:]: x["data"] for x in known_profiles}
    profiles = known_profiles
    all_interfaces = []

    for file in BACKUP_DIR.glob("*.oc"):
        with open(file, "r") as f:
            data = json.load(f)
            interfaces = data.get("interfaces", [])
            for interface in interfaces:
                # if 'routed-vlan' in interface:
                #     continue
                profile = interface.copy()
                del profile["name"]
                if profile.get("config", {}).get("name"):
                    del profile["config"]["name"]
                profile.get("config", {}).pop("description", None)
                if profile not in profiles.values():
                    print(
                        f"New profile detected: {data.get('system', {}).get('config', {}).get('hostname')} -> {interface.get('name')}"
                    )
                    profile_name = uuid.uuid4().hex
                    profiles[profile_name] = profile
                else:
                    for key, item in profiles.items():
                        if item == profile:
                            profile_name = key
                            break
                all_interfaces.append(
                    {
                        "device": data.get("system", {})
                        .get("config", {})
                        .get("hostname"),
                        "interface": interface,
                        "profile": profile_name,
                    }
                )
    return profiles, all_interfaces

def change_port_profile_name(old_name, new_name):
    if old_name == new_name:
        return (False, "Old name is the same as new....")
    netbox = Netbox()
    port_profile = netbox._get(f"/api/extras/config-contexts/?name={old_name}")[0]
    port_profile['name'] = new_name
    del port_profile['data_source']
    tag_info = netbox._get(f"/api/extras/tags/?name={old_name}")[0]
    tag_info['name'] = new_name

    tag_result, tag_msg = netbox._patch(f"/api/extras/tags/", data=[tag_info])
    context_result, context_msg = netbox._patch(f"/api/extras/config-contexts/", data=[port_profile])
    if tag_result and context_result:
        return (True, f"Name change succesful (changed tag and profile name in netbox)")
    else:
        return (False, f"Error changing tag in Netbox {tag_msg}{context_msg}")


def get_port_profiles_from_device(hostname):
    netbox = Netbox()
    known_profiles = netbox._get("/api/extras/config-contexts/?name__isw=pp:")
    known_profiles = {x["name"][3:]: x["data"] for x in known_profiles}
    profiles = known_profiles
    all_interfaces = []

    with open(BACKUP_DIR.joinpath(f"{hostname}.oc"), "r", encoding="utf-8") as f:
        data = json.load(f)
        interfaces = data.get("interfaces", [])
        for interface in interfaces:
            # if 'routed-vlan' in interface:
            #     continue
            profile = interface.copy()
            del profile["name"]
            if profile.get("config", {}).get("name"):
                del profile["config"]["name"]
            profile.get("config", {}).pop("description", None)
            if profile not in profiles.values():
                print(
                    f"New profile detected: {data.get('system', {}).get('config', {}).get('hostname')} -> {interface.get('name')}"
                )
                profile_name = uuid.uuid4().hex
                profiles[profile_name] = profile
            else:
                for key, item in profiles.items():
                    if item == profile:
                        profile_name = key
                        break
            all_interfaces.append(
                {
                    "name": interface["name"],
                    "interface": interface,
                    "profile": profile_name,
                }
            )
    return profiles, all_interfaces


def save_port_profiles(profiles):
    netbox = Netbox()
    known_profiles = netbox._get("/api/extras/config-contexts/?name__isw=pp:")
    known_profiles = {x["name"][3:]: x["data"] for x in known_profiles}
    for name, profile in profiles.items():

        if name in known_profiles:
            continue
        # Create tag
        new_tag_data = {
            "name": f"pp:{name}",
            "slug": f"pp-{name}",
            "color": "607d8b",
            "description": "Port profile",
            "object_types": [
                "dcim.devicerole",
                "dcim.sitegroup",
                "ipam.role",
                "ipam.vlangroup",
            ],
        }
        netbox._post(endpoint="/api/extras/tags/", data=new_tag_data)

        # Create context in netbox
        new_context_data = {
            "name": f"pp:{name}",
            "weight": 1000,
            "description": "Port Profile",
            "tags": [f"pp-{name}"],
            "data": profile,
        }
        logger.debug(
            netbox._post(endpoint="/api/extras/config-contexts/", data=new_context_data)
        )
