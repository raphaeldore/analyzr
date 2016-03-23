import abc
import logging
from collections import namedtuple
from typing import NamedTuple, List, Set, Tuple

import netaddr


class NetworkNode(object):
    """
    Represents a node in the network.
    """

    # ip - mac - host - hops - opened_ports - closed_ports - possibles fingerprints
    str_template = "{0:15s}|{1:17s}|{2:3s}|{3:30s}|{4:15s}|{5:15s}|6:30s}"

    def __init__(self, ip: netaddr.IPAddress = None, mac: netaddr.EUI = None, host: str = None):
        self.ip = ip
        self.mac = mac
        self.host = host
        self.possible_fingerprints = set()
        self.opened_ports = []
        self.closed_ports = []
        self.hops = []

    def __eq__(self, other: netaddr.IPAddress):
        return self.ip == other

    def __hash__(self):
        return self.ip.__hash__()

    def __str__(self):
        return self.str_template.format(
            str(self.ip),
            str(self.mac),
            self.host or "Unknown host",
            "{nb_hops} hops : {hops}".format(nb_hops=len(self.hops), hops=" --> ".join(hop for hop in self.hops)),
            str(self.opened_ports).strip("[]"),
            str(self.closed_ports).strip("[]"),
            ", ".join(str(e) for e in self.possible_fingerprints))


class AnalyzrModule(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.config = {}


class InvalidInterface(Exception):
    pass


DiscoveredHost = namedtuple("DiscoveredHost", ["ip", "mac"])
PingedHost = namedtuple("PingedHost", ["ip", "ttl"])
HostInfo = NamedTuple("HostInfo", [("ip", str), ("ip_network", str), ("gateway_ip", str), ("dhcp_server_ip", str),
                                   ("interface_name", str)])


class NetworkToolFacade(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, fingerprinters: list, interface_to_use: str = None):
        """
        Inits the object. Raises InvalidInterface exception if given interface is invalid (maps to no interface
        on the host).

        :param fingerprinters: List of fingerprinters (See Fingerprinter) to use to identify packet.
        :param interface_to_use: the network interface used by the tool. if "auto" or None, then it is automagically
        selected (which one is chosen depends on the NetworkTool, but best bet is on the primary network interface).
        """
        self.fingerprinters = fingerprinters
        self.interface_to_use = interface_to_use

    @property
    @abc.abstractmethod
    def host_information(self) -> HostInfo:
        pass

    @abc.abstractmethod
    def arp_discover_hosts(self,
                           network: str,
                           timeout: int,
                           verbose: bool = False) -> List[DiscoveredHost]:
        """
        Returns list of DiscoveredHost
        :param network:
        :param timeout:
        :param verbose:
        """
        pass

    @abc.abstractmethod
    def passive_discover_hosts(self,
                               networks: List[str],
                               timeout_in_secs: int) -> List[DiscoveredHost]:
        """

        :param networks: Only check for traffic that comes from these networks.
                         Networks must be in CIRD format (I.E: 192.168.1.0/24)

        :param timeout_in_secs: Number of seconds to passively scan the network before stopping.
        """

    @abc.abstractmethod
    def route_to_target(self, target_ip: str):
        """
        Returns route to target, or an empty list if no route found.

        :param target_ip: target ip address
        :return: A list containing the trace of IPs to get to target.
        """
        pass

    @abc.abstractmethod
    def icmp_ping(self, ip: str, timeout: int, verbose: bool) -> PingedHost:
        """
        If host exists, will return a PingedHost namedtuple. Else returns None.

        :param ip: The ip to icmp_ping
        :param timeout:  Time before giving up
        :param verbose: If set to True, there may be logs in stdout.
        """
        pass

    @abc.abstractmethod
    def identify_host_os(self, ip: str) -> Set[str]:
        """
        Tries to identify the operating system of the host at the given IP.

        Returns None if nothing found. Else return a set of possible matches.

        :param ip: The host to probe
        """
        pass

    @abc.abstractmethod
    def tcp_port_scan(self, ip: str, ports_to_scan: List[int]) -> Tuple[List[int], List[int]]:
        """
        Checks each port of ports_to_scan to see if it is opened on the host.

        Returns tuple: list of opened ports (sorted in order), list of closed ports (sorted in order).
        Never returns None. Both lists will always be at least empty.

        :param ip: The ip to scan for opened ports
        :param ports_to_scan: The ports to scan on the host.

        :returns tuple opened_ports, closed_ports.
        """
        pass

    @staticmethod
    @abc.abstractmethod
    def pkt_to_ettercap_fn() -> callable:
        """
        Returns a function that converts a pkt for processing by a fingerprinter.
        """
        pass

    @abc.abstractmethod
    def sniff_network(self,
                      nb_pkts_to_sniff: int,
                      store_sniffed_pkts: bool,
                      timeout_in_secs: int = None,
                      pkt_callback_fn: callable = None,
                      pkt_filter_fn: callable = None,
                      stop_filter_fn: callable = None) -> list:
        pass


class Fingerprinter(AnalyzrModule):
    def __init__(self, name: str, os_fingerprint_file_name: str, pkt_conversion_fn: callable):
        super().__init__(name)
        self.os_fingerprint_file_name = os_fingerprint_file_name
        self.pkt_conversion_fn = pkt_conversion_fn
        self.logger = logging.getLogger(__name__)

    def load_fingerprints(self):
        raise NotImplemented

    def identify_os_from_pkt(self, pkt) -> set:
        raise NotImplemented
