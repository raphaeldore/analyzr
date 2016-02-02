"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
import errno
from scapy.all import *
from netaddr import *
from scapy.layers.l2 import arping
from scapy.layers.inet import IP, TCP, ICMP
from collections import namedtuple

from analyzr.utils import to_CIDR_notation

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

LiveHost = namedtuple("LiveHost", ["ip", "mac"])

# Define TCP port range to scan
portRange = [22, 23, 80, 443, 449, 3389, 161]


class NetworkScanner:
    def __init__(self):
        self.host_ip_address = ""
        self.networks_interfaces = {}
        self.read_networks_interfaces()
        self.live_network_hosts = dict()  # (network --> (ip --> mac, ip --> mac, ip --> mac))

    def read_networks_interfaces(self):
        for network, netmask, gateway, interface, address in scapy.config.conf.route.routes:

            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            cidr = to_CIDR_notation(network, netmask)

            if not cidr:
                continue

            ip_network = IPNetwork(cidr)

            if interface != scapy.config.conf.iface:
                logger.warn(
                        "Skipping %s because scapy currently doesn't support arping on non-primary network interfaces",
                        ip_network.cidr)
                continue

            if ip_network is None:
                continue

            self.networks_interfaces[interface] = ip_network

    def get_host_network(self):
        return ""

    def port_ping_scan(self):
        try:
            for interface, network in self.networks_interfaces.items():
                # Toutes les addresses possibles du réseau
                for addr in list(network):
                    if addr == network.broadcast:
                        continue

                    portScan(str(addr), portRange)
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

    def scan_and_find_live_hosts_on_networks(self, timeout=1):
        try:
            for interface, network in self.networks_interfaces.items():
                ans, unans = scapy.layers.l2.arping(str(network), iface=interface, timeout=timeout, verbose=False)
                for s, r in ans.res:
                    #self.live_network_hosts.setdefault(str(network), {}).[str(network)][r.psrc] = r.hwsrc
                    #self.live_network_hosts.setdefault(str(network), []).append({r.psrc, r.hwsrc})
                    self.live_network_hosts.setdefault(str(network), []).append(LiveHost(ip = r[ARP].psrc, mac = r[ARP].hwsrc))
                    #self.live_network_hosts[str(network)][r.psrc] = r.hwsrc
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        print("DONE!")

    def pretty_print_ips(self):
        for network, live_hosts in self.live_network_hosts.items():
            for live_host in live_hosts:
                logger.debug("{0:s}:{1:s}".format(live_host.ip, live_host.mac))
                #print("{0:s}:{0:s}".format(str(live_host.ip), str(live_host.mac)))


def portScan(host, ports):
    # Send SYN with random Src Port for each Dst port
    for dstPort in ports:
        srcPort = random.randint(1025, 65534)
        resp = sr1(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="S"), timeout=1, verbose=0)
        if resp is None:
            logger.info(host + ":" + str(dstPort) + " is filtered (silently dropped).")
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="R"), timeout=1, verbose=0)
                logger.info(host + ":" + str(dstPort) + " is open.")
            elif resp.getlayer(TCP).flags == 0x14:
                logger.info(host + ":" + str(dstPort) + " is closed.")
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    logger.info(host + ":" + str(dstPort) + " is filtered (silently dropped).")
