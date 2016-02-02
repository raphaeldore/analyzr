"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
import errno
from scapy.all import *
from netaddr import *
from scapy.layers.inet import IP, TCP, ICMP

from analyzr.utils import to_CIDR_notation

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Define TCP port range to scan
portRange = [22, 23, 80, 443, 449, 3389, 161]


class NetworkScanner:
    def __init__(self):
        self.host_ip_address = ""
        self.networks_interfaces = {}
        self.read_networks_interfaces()

    def read_networks_interfaces(self):
        for network, netmask, gateway, interface, address in scapy.config.conf.route.routes:

            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            ip_network = IPNetwork(to_CIDR_notation(network, netmask))

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