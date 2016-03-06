import abc
import threading
from collections import namedtuple
from typing import List, Tuple

from analyzr import constants
from analyzr.constants import NUM_PING_THREADS, TCPFlag

ArpDiscoveredHost = namedtuple("ArpDiscoveredHost", ["ip", "mac"])
PingedHost = namedtuple("PingedHost", ["ip", "ttl"])
HostInfo = namedtuple("HostInfo", ["ip", "ip_network", "gateway_ip", "dhcp_server_ip", "interface_name"])


class NetworkToolFacade(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, interface_to_use: str = None):
        """
        Inits the object. Raises InvalidInterface exception if given interface is invalid (maps to no interface
        on the host).

        :param interface_to_use: the network interface used by the tool
        """
        self.interface_to_use = interface_to_use

    @abc.abstractproperty
    def host_information(self) -> HostInfo:
        pass

    @abc.abstractmethod
    def arp_discover_hosts(self,
                           network: str,
                           timeout: int,
                           verbose: bool = False) -> List[ArpDiscoveredHost]:
        """
        Returns list of ArpDiscoveredHost
        :param network:
        :param timeout:
        :param verbose:
        """
        pass

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
    def identify_host_os(self, ip: str) -> str:
        """
        Tries to identify the operating system of the host at the given IP.

        Returns None if nothing found.

        :param ip: The host to probe
        """
        pass

    @abc.abstractmethod
    def tcp_port_scan(self, ip: str, ports_to_scan: List[int]) -> Tuple[List[int], List[int]]:
        """
        Checks each port of ports_to_scan to see if it is opened on the host.

        Returns tuple: list of opened ports (sorted in order), list of closed ports (sorted in order).
        Never returns None. Both lists will always be at least empty.
        :param ip:
        :param ports_to_scan:
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
from scapy.layers.inet import IP, ICMP, TCP, traceroute
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

        self.logger = logging.getLogger(__name__)

        self.cached_host_info = self.host_information()
        if not self.cached_host_info:
            raise InvalidInterface

        self.logger.debug("Current host info: {}".format(self.cached_host_info))

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
        ans = srp1(ether / ip / udp / bootp / dhcp, timeout=10)

        if ans and DHCP in ans:
            message_type = ans[DHCP].options[0][1]
            if message_type == constants.DhcpMessageTypes.MESSAGE_TYPE_OFFER:
                return ans[IP].psrc

        return None

    def arp_discover_hosts(self,
                           network: str,
                           timeout: int,
                           verbose: bool = False) -> List[ArpDiscoveredHost]:
        from scapy.layers.l2 import arping
        ans, unans = arping(network, iface=self.interface_to_use, timeout=timeout, verbose=verbose)

        macs_ips = []
        for s, r in ans.res:
            macs_ips.append(ArpDiscoveredHost(ip=r[ARP].psrc, mac=r[Ether].src))

        return macs_ips

    def route_to_target(self, target_ip: str):
        res, unans = traceroute(target_ip, timeout=10)
        hops = []

        if res:

            # Trace looks like this:
            # {'216.58.219.238':                            <-- Destination ip
            #     {
            #         1: ('172.16.2.1', False),             <-- Packet number : (IP, ???? is end??)
            #         3: ('10.170.183.93', False),
            #         4: ('216.113.126.214', False),
            #         5: ('72.14.216.117', False),
            #         6: ('209.85.248.178', False),
            #         7: ('64.233.174.117', False),
            #         8: ('216.58.219.238', True)
            #     }
            # }

            trace = res.get_trace()
            host_key = next(iter(trace.keys()))  # Returns the IP of the host (Ex: 216.58.219.238)

            # for each Packet number : (IP, ???? is end??)
            for key in res.get_trace()[host_key]:
                hops.append(trace[host_key][key][0])  # Append IP (first value in tuple)

        return hops

    def icmp_ping(self, ip: str, timeout: int, verbose: bool) -> PingedHost:
        res = sr1(IP(dst=ip) / ICMP(), iface=self.interface_to_use, timeout=timeout, verbose=verbose)
        return PingedHost(ip=ip, ttl=res[IP].ttl) if res else None

    def identify_host_os(self, ip: str) -> str:
        pass

    def tcp_port_scan(self, ip: str, ports_to_scan: List[int]) -> Tuple[List[int], List[int]]:
        ports_queue = queue.Queue()
        opened_ports = []

        for thread_nbr in range(NUM_PING_THREADS):
            t = threading.Thread(
                target=self._scan_ports_thread,
                args=(ip, ports_queue, opened_ports,),
                daemon=True,
                name="Port scan worker #{0:d} ({1:s})".format(thread_nbr, ip)
            )
            t.start()

        # On rempli la file...
        [ports_queue.put(port) for port in ports_to_scan]

        ports_queue.join()

        closed_ports = [port for port in ports_to_scan if port not in opened_ports]

        # Sort ports in order (I.E: we want 80, 443 NOT 443, 80).
        opened_ports.sort(key=int)
        closed_ports.sort(key=int)

        return opened_ports, closed_ports

    def _scan_ports_thread(self, host, ports_queue: queue.Queue, opened_ports: list):
        while True:
            port = ports_queue.get()
            self.logger.debug("{0:s} : Scanning port {1:d}.".format(threading.current_thread().name, port))

            # Send SYN with random Src Port for each Dst port
            srcPort = random.randint(1025, 65534)
            resp = sr1(IP(dst=host) / TCP(sport=srcPort, dport=port, flags="S"), timeout=1)
            if resp and resp.haslayer(TCP):
                if resp[TCP].flags == (TCPFlag.SYN | TCPFlag.ACK):
                    # YAY the port is opened
                    self.logger.debug("{thread_name} : port {port} is opened!"
                                      .format(thread_name=threading.current_thread().name, port=port))
                    opened_ports.append(port)
                    # Send RST to close connection.
                    send(IP(dst=host) / TCP(sport=srcPort, dport=port, flags="R"))
                    # elif ICMP in resp:
                    #    if int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    #        # Port state unknown... TODO: we should retry

            ports_queue.task_done()

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
