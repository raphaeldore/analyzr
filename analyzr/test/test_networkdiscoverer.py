import unittest

from analyzr.constants import topports
from analyzr.core import NetworkToolFacade, Fingerprinter
from analyzr.networkdiscoverer import NetworkDiscoverer


class NetworkToolMock(NetworkToolFacade):
    pass


class FingerprinterMock(Fingerprinter):
    pass


class InitConfig(unittest.TestCase):
    def setUp(self):
        fingerprinters = [FingerprinterMock("abc", "whatever", None)]
        self.network_tool = NetworkToolMock(fingerprinters)
        self.config = {"ports": None, "networks": None, "discovery_mode": None}

    def get_network_discoverer(self):
        return NetworkDiscoverer(self.network_tool, self.config)

    def test_when_no_ports_given_then_default_ports_used(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.ports_to_scan, topports)

    def test_when_config_does_not_have_ports_key_then_default_ports_used(self):
        self.config.pop("ports")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.ports_to_scan, topports)

    def test_when_no_networks_given_then_default_networks_used(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.networks_to_scan, network_discoverer.private_ipv4_space)

    def test_when_config_does_not_have_networks_key_then_default_networks_used(self):
        self.config.pop("networks")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.networks_to_scan, network_discoverer.private_ipv4_space)

    def test_when_no_discovery_mode_given_then_default_default_discovery_mode_used(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.discovery_mode, "all")

    def test_when_config_does_not_have_discovery_mode_key_then_default_descovery_mode_all_used(self):
        self.config.pop("discovery_mode")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.discovery_mode, "all")

    # TODO: Tester que les valeurs sont bien affectés.


if __name__ == '__main__':
    unittest.main()
