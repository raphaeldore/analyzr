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

    def test_given_no_ports_to_scan_then_uses_default_ports(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.ports_to_scan, topports)

    def test_given_config_with_no_ports_to_scan_then_uses_default_ports(self):
        self.config.pop("ports")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.ports_to_scan, topports)

    def test_given_no_networks_to_scan_then_uses_default_networks(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.networks_to_scan, network_discoverer.private_ipv4_space)

    def test_given_config_with_no_networks_to_scan_then_uses_default_networks(self):
        self.config.pop("networks")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.networks_to_scan, network_discoverer.private_ipv4_space)

    def test_given_no_discovery_mode_then_default_discovery_mode_used(self):
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.discovery_mode, "all")

    def test_given_config_with_no_discory_mode_then_default_descovery_mode_used(self):
        self.config.pop("discovery_mode")
        network_discoverer = self.get_network_discoverer()
        self.assertEqual(network_discoverer.discovery_mode, "all")

    # TODO: Tester que les valeurs sont bien affectés.


if __name__ == '__main__':
    unittest.main()
