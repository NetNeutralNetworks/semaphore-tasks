from scripts.base import Script
from nc_mis.drivers.abstract import Platform

class CheckHealthScript(Script):
    required_args = []
    optional_args = []
    ## supported_platforms should not be implemented in core code. 
    supported_platforms = [Platform.JUNOS, Platform.ARUBAOS_CX, Platform.HP_PROCURVE]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self):
        self.job.driver.health_check()
