from netaddr import IPAddress, EUI
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr1, sr

from analyzr.core import config
from analyzr.core.entities import NetworkNode
from analyzr.networkdiscovery.scanner import Scanner
from analyzr.topports import topports
from analyzr.utils.network import resolve_ip, TCPFlag

logger = logging.getLogger(__name__)


class ArpPing(Scanner):
    def __init__(self):
        super(ArpPing, self).__init__()

    def scan(self):
        try:
            for interface, network in config.interfaces_networks.items():
                if not network.is_private():
                    self.logger.info(
                        "Skipping arp ping scan on network {0:s} because it's a public network".format(str(network)))
                    continue

                self.logger.info("Executing arp ping scan on network {0:s}...".format(str(network)))
                discovered_hosts = set()
                ans, unans = scapy.layers.l2.arping(str(network), iface=interface, timeout=1, verbose=False)
                for s, r in ans.res:
                    node = NetworkNode()
                    node.ip = IPAddress(r[ARP].psrc)
                    node.mac = EUI(r[Ether].src)
                    node.host = resolve_ip(r[ARP].psrc)
                    discovered_hosts.add(node)

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("Arp ping scan done. Found %d unique hosts.", self.number_of_hosts_found)


class ICMPPing(Scanner):
    def __init__(self):
        super(ICMPPing, self).__init__()

    def scan(self):
        try:
            for interface, network in config.interfaces_networks.items():
                if network.is_private() and not config.scan_local_network_as_public:
                    self.logger.info(
                        "Skipping ICMP ping scan on network {0:s} because it's a private network.".format(str(network)))
                    continue

                self.logger.info("Executing ICMP ping scan on network {0:s}...".format(str(network)))
                discovered_hosts = set()
                ans, unans = sr(IP(dst=str(network)) / ICMP(), iface=interface, timeout=2)
                self.logger.debug(u"Got {0:d} answers.".format(len(ans)))
                for s, r in ans.res:
                    node = NetworkNode()
                    node.ip = IPAddress(r[IP].src)
                    node.mac = EUI(r[Ether].src)
                    node.host = resolve_ip(r[Ether].src)
                    discovered_hosts.add(node)

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("ICMP ping scan done. Found %d unique hosts.", self.number_of_hosts_found)


class TCPSYNPing(Scanner):
    def __init__(self):
        super(TCPSYNPing, self).__init__()
        if config.fastTCP:
            self.portstoscan = [80]
        else:
            self.portstoscan = topports

    def scan(self):
        try:
            for interface, network in config.interfaces_networks.items():
                if network.is_private() and not config.scan_local_network_as_public:
                    self.logger.info(
                        "Skipping TCP ACK Ping on {0:s} because it's a private network.".format(str(network)))
                    continue

                if config.fastTCP:
                    self.logger.info("Executing TCP SYN ping scan (fast version) on {0:s}...".format(str(network)))
                else:
                    self.logger.info("Executing TCP SYN ping scan (slow version) on {0:s}...".format(str(network)))

                self.logger.info("Scanning ports %s.", str(self.portstoscan).strip("[]"))

                discovered_hosts = set()

                srcPort = random.randint(1025, 65534)
                ans, unans = sr(IP(dst=str(network)) / TCP(sport=srcPort, dport=self.portstoscan, flags="S"),
                                iface=interface, timeout=10, verbose=False)

                self.logger.debug(u"Got {0:d} answers.".format(len(ans)))

                for s, r in ans.res:
                    node = NetworkNode()
                    node.ip = IPAddress(r[IP].src)
                    node.mac = EUI(r.src)
                    node.host = resolve_ip(r[IP].src)
                    discovered_hosts.add(node)

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("TCP SYN ping scan done. Found %d unique hosts.", self.number_of_hosts_found)

    def _portScan(self, host, ports, interface):
        # Send SYN with random Src Port for each Dst port
        for dstPort in ports:
            srcPort = random.randint(1025, 65534)
            resp = sr1(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="S"), timeout=1, verbose=0,
                       iface=interface)
            if resp is None:
                # No response... we cannot know if host exists (port is probably filtered, aka silently dropped).
                # Let's try the next port.
                continue
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == (TCPFlag.SYN | TCPFlag.ACK) or resp.getlayer(
                        TCP).flags == (TCPFlag.RST | TCPFlag.ACK):
                    send_rst = sr(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="R"), timeout=1, verbose=0,
                                  iface=interface)
                    # We know the port is closed or opened (we got a response), so we deduce that the host exists
                    node = NetworkNode()
                    node.ip = IPAddress(resp[IP].src)
                    node.mac = EUI(resp.src)
                    node.host = resolve_ip(resp[IP].src)
                    return NetworkNode
                elif resp.haslayer(ICMP):
                    # We cannot determine if host exists (port is probably filtered, aka silently dropped).
                    # Let's try the next port.
                    continue

        return None
