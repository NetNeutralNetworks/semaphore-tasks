from typing import List, Optional, Dict
from diffsync import DiffSyncModel

class Manufacturer(DiffSyncModel):

    _modelname = "manufacturer"
    _identifiers = ("name",)
    _shortname = ()
    _attributes = ("display", "slug", "description")
    _children = {"device_type": "device_types", 'module_type': "module_types"}

    name: str
    display: str
    slug: str
    description: str 
    device_types: List = list()
    module_types: List = list()
    database_pk: Optional[int] = None

class DeviceType(DiffSyncModel):

    _modelname = "device_type"
    _identifiers = ("model",)
    _shortname = ()
    _attributes = (
        "slug",
        "manufacturer_name",
        "part_number",
        "is_full_depth", 
        "airflow", 
        "weight",
        "weight_unit",
        "description",
        "comments",)
    _children = {
        'interface_template': 'interface_templates', 
        'power_port_template': 'power_port_templates', 
        'console_port_template': 'console_port_templates',
        'module_bay_template': 'module_bay_templates',
        }

    model: str
    slug: str
    manufacturer_name: str
    part_number: str
    is_full_depth: bool
    airflow: Optional[Dict]
    weight: Optional[float]
    weight_unit: Optional[Dict]
    description: str 
    comments: str
    interface_templates: List = list()
    power_port_templates: List = list()
    console_port_templates: List = list()
    module_bay_templates: List = list()
    database_pk: Optional[int] = None

class ModuleType(DiffSyncModel):

    _modelname = "module_type"
    _identifiers = ("model",)
    _shortname = ()
    _attributes = (
        "manufacturer_name",
        "part_number",
        "weight",
        "weight_unit",
        "description",
        "comments",)
    _children = {'interface_template': 'interface_templates'}

    model: str
    manufacturer_name: str
    part_number: str
    weight: Optional[float]
    weight_unit: Optional[Dict]
    description: str 
    comments: str
    interface_templates: List = list()
    database_pk: Optional[int] = None
    

class InterfaceTemplate(DiffSyncModel):

    _modelname = "interface_template"
    _identifiers = ("device_type","module_type","name")
    _shortname = ()
    _attributes = (
        "interface_type",
        "enabled",
        "mgmt_only",
        "description", 
        "bridge", 
        "poe_mode",
        "poe_type",
        "rf_role",)
    _children = {}

    device_type: str
    name: str
    module_type : str
    interface_type: Dict
    enabled: bool
    mgmt_only: bool
    description: str
    bridge: Optional[Dict]
    poe_mode: Optional[Dict]
    poe_type: Optional[Dict]
    rf_role: Optional[Dict]
    database_pk: Optional[int] = None

class PowerPortTemplate(DiffSyncModel):

    _modelname = "power_port_template"
    _identifiers = ("device_type","module_type","name")
    _shortname = ()
    _attributes = (
        "type",
        "maximum_draw",
        "allocated_draw", 
        "description", 
    )
    _children = {}

    device_type: str
    name: str
    module_type : str
    type: str
    maximum_draw: Optional[int]
    allocated_draw: Optional[int]
    description: str
    database_pk: Optional[int] = None
    
class ConsolePortTemplate(DiffSyncModel):

    _modelname = "console_port_template"
    _identifiers = ("device_type","module_type","name")
    _shortname = ()
    _attributes = (
        "type",
        "description", 
    )
    _children = {}

    device_type: str
    name: str
    module_type : str
    type: str
    description: str
    database_pk: Optional[int] = None

class ModuleBayTemplate(DiffSyncModel):

    _modelname = "module_bay_template"
    _identifiers = ("device_type","name")
    _shortname = ()
    _attributes = (
        "label",
        "position",
        "description", 
    )
    _children = {}

    device_type: str
    name: str
    label: str
    position: str
    description: str
    database_pk: Optional[int] = None
    

class Site(DiffSyncModel):

    _modelname = "site"
    _identifiers = ("name",)
    _shortname = ()
    _attributes = (
        "slug",
        "status",
        "description",
        "comments", 
    )
    _children = {}

    name: str
    slug: str
    status: str
    description: str
    comments: str
    database_pk: Optional[int] = None

class DeviceRole(DiffSyncModel):

    _modelname = "device_role"
    _identifiers = ("name",)
    _shortname = ()
    _attributes = (
        "slug",
        "color",
        "vm_role",
        "description", 
    )
    _children = {}

    name: str
    slug: str
    color: str
    vm_role: bool
    description: str
    database_pk: Optional[int] = None

class Device(DiffSyncModel):

    _modelname = "device"
    _identifiers = ("hostname",)
    _shortname = ()
    _attributes = (
        "serial",
        "device_type",
        "status", 
    )
    _children = {}

    serial: str
    hostname: str
    device_type: str
    status: str
    database_pk: Optional[int] = None