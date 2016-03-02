import abc
from _ast import List
from collections import namedtuple

from analyzr import constants

ArpDiscoveredHost = namedtuple("ArpDiscoveredHost", ["ip", "mac"])
PingedHost = namedtuple("PingedHost", ["ip", "ttl"])
HostInfo = namedtuple("HostInfo", ["ip", "ip_network", "gateway_ip", "dhcp_server_ip", "interface_name"])


class NetworkToolFacade(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, interface_to_use=None):
        self.interface_to_use = interface_to_use

    @abc.abstractproperty
    def host_information(self) -> HostInfo:
        pass

    @abc.abstractmethod
    def arp_discover_hosts(self, network: str, timeout: int,
                           verbose: bool = False) -> list:  # Python 3.5 List[ArpDiscoveredHost]:
        """
        Returns list of ArpDiscoveredHost
        :param network:
        :param timeout:
        :param verbose:
        """
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
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet import UDP


class InvalidInterface(Exception):
    pass


class ScapyTool(NetworkToolFacade):
    # Removes "WARNING: Mac address to reach destination not found. Using broadcast" message.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    cached_host_info = None
    def __init__(self, interface_to_use=None):
        from scapy.all import conf
        # Make scapy shut up while sending packets
        conf.verb = 0

        if not interface_to_use:
            interface_to_use = conf.iface

        super().__init__(interface_to_use)

        self.cached_host_info = self.host_information()
        if not self.cached_host_info:
            raise InvalidInterface

    def host_information(self) -> HostInfo:
        if self.cached_host_info:
            return self.cached_host_info

        from analyzr.utils.network import int2ip
        from analyzr.utils.network import long2netmask

        for network_int, netmask_int, gateway, interface, address in conf.route.routes:
            if interface != self.interface_to_use:
                continue

            # invalid netmask
            if netmask_int <= 0 or netmask_int == 0xFFFFFFFF:
                continue

            network = int2ip(network_int)
            # other way: netmask = bin(network_int).count("1")
            netmask = long2netmask(netmask_int)

            # A host will never be connected to a network < /16
            if netmask < 16:
                continue

            return HostInfo(ip=address,
                            ip_network=network,
                            gateway_ip=gateway,
                            dhcp_server_ip=self._get_dhcp_server_ip(),
                            interface_name=interface)

        return None

    def _get_dhcp_server_ip(self):
        conf.checkIPaddr = False
        hw = get_if_hwaddr(self.interface_to_use)
        ether = Ether(dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=hw)
        dhcp = DHCP(options=[('message-type', 'discover'), 'end'])

        # Send packet
        ans = srp1(ether / ip / udp / bootp / dhcp)

        if ans and DHCP in ans:
            message_type = ans[DHCP].options[0][1]
            if message_type == constants.DhcpMessageTypes.MESSAGE_TYPE_OFFER:
                return ans[IP].psrc

        return None

    def arp_discover_hosts(self, network: str, timeout: int,
                           verbose: bool = False) -> list:  # type: List[ArpDiscoveredHost]
        from scapy.layers.l2 import arping
        ans, unans = arping(network, iface=self.interface_to_use, timeout=timeout, verbose=verbose)

        macs_ips = []
        for s, r in ans.res:
            macs_ips.append(ArpDiscoveredHost(ip=r[ARP].psrc, mac=r[Ether].src))

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
