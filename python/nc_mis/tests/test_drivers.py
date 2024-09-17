import unittest

from drivers.aruba.aos.AOS import AOS
from drivers.juniper.JUNOS import JUNOS
from helpers.logger import logger


class TestJuniper(unittest.TestCase):
    device = JUNOS(ip="0.0.0.0",
                    username="user",
                    password="password"
                    )

    def setUp(self):
        logger()

    def test_JUNOS_deploy_config(self):
        with self.device as connected_device:
            connected_device.send_configlet(commands = [
                "set interfaces xe-0/0/0 description testing",
                "set interfaces xe-0/0/1 description testing"])

    def tearDown(self):
        with self.device as connected_device:
            connected_device.rollback()

class TestAruba(unittest.TestCase):
    device = AOS(ip='0.0.0.0',
                username='user',
                password='password')

    def setUp(self):
        logger()

    def test_AOS_get_config(self):
        print(self.device.get_config())

    def test_AOS_deploy_config(self):
        result = self.device.send_configlet(["logging 0.0.0.0",
                                             "logging 0.0.0.0"
                                             ], dryrun=False, save_config=False)
        print(result)

    def tearDown(self):
        self.device.rollback()

if __name__ == '__main__':
    unittest.main()
