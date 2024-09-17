from scripts.base import Script
from nc_mis.drivers.abstract import Platform

class GetBackupScript(Script):
    required_args = []
    optional_args = []
    supported_platforms = ['arubaos-cx', Platform.JUNOS]
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def execute(self, device_info):
        output = []
        config = self.job.driver.backup_config()