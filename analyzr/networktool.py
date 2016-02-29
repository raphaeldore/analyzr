import abc
from collections import namedtuple

ArpDiscoveredHost = namedtuple("ArpDiscoveredHost", ["ip", "mac"])
PingedHost = namedtuple("PingedHost", ["ip", "ttl"])


class NetworkToolFacade(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, interface_to_use=None):
        self.interface_to_use = interface_to_use

    @abc.abstractmethod
    def arp_discover_hosts(self, network: str, timeout: int, verbose: bool) -> list(ArpDiscoveredHost):
        pass

    @abc.abstractmethod
    def ping(self, ip: str, timeout: int, verbose: bool) -> PingedHost:
        """
        If host exists, will return a PingedHost namedtuple. Else returns None.

        :param ip: The ip to ping
        :param timeout:  Time before giving up
        :param verbose: If set to True, there may be logs in stdout.
        """
        pass

    @abc.abstractmethod
    def identify_host_os(self, ip: str) -> str:
        """
        Tries to identify the operating system of the host at the given IP.

        Returns None if nothing found.

        :param ip: The host to probe
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


from scapy.all import *
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP


class ScapyTool(NetworkToolFacade):
    def __init__(self, interface_to_use=None):
        if not interface_to_use:
            from scapy.all import conf
            interface_to_use = conf.iface

        super().__init__(interface_to_use)

    def arp_discover_hosts(self, network: str, timeout: int, verbose: bool) -> list(ArpDiscoveredHost):
        from scapy.layers.l2 import arping
        ans, unans = arping(network, iface=self.interface_to_use, timeout=timeout, verbose=verbose)

        macs_ips = []
        for s, r in ans.res:
            macs_ips.append(ArpDiscoveredHost(ip=r[ARP].psr, mac=r[ARP].psrc))

        return macs_ips

    def ping(self, ip: str, timeout: int, verbose: bool) -> PingedHost:
        res = sr1(IP(dst=ip) / ICMP(), iface=self.interface_to_use, timeout=timeout, verbose=verbose)
        return PingedHost(ip=ip, ttl=res[IP].ttl) if res else None

    def identify_host_os(self, ip: str) -> str:
        pass

    def sniff_network(self,
                      nb_pkts_to_sniff: int,
                      store_sniffed_pkts: bool,
                      timeout_in_secs: int = None,
                      pkt_callback_fn: callable = None,
                      pkt_filter_fn: callable = None,
                      stop_filter_fn: callable = None) -> list:
        from scapy.sendrecv import sniff
        ans = sniff(count=nb_pkts_to_sniff,
                    offline=1 if store_sniffed_pkts else 0,
                    prn=pkt_callback_fn,
                    lfilter=pkt_filter_fn,
                    timeout=timeout_in_secs,
                    iface=self.interface_to_use)

        # TODO: Wrap this in a class
        return ans
