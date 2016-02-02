"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
import errno
from collections import namedtuple

from netaddr import *
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import arping

from .portscanthread import PortScanThread
from .topports import topports
from .utils import to_CIDR_notation

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

LiveHost = namedtuple("LiveHost", ["ip", "mac"])


class NetworkScanner:
    def __init__(self):
        self.host_ip_address = ""
        self.networks_interfaces = {}
        self.live_network_hosts = dict()  # (network --> (ip --> mac, ip --> mac, ip --> mac))
        self.__read_networks_interfaces()

    def __read_networks_interfaces(self):
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

                    portScan(str(addr), topports)
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
                    self.live_network_hosts.setdefault(str(network), []).append(
                        LiveHost(ip=r[ARP].psrc, mac=r[Ether].src))
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

    def find_hops(self):
        iphops = dict()
        for network, live_hosts in self.live_network_hosts.items():
            for live_host in live_hosts:
                for hops in range(1, 28): # Max 4 hops..on reste sur le réseau local
                    reply = sr1(IP(dst=live_host.ip, ttl=hops) / UDP(dport=40000), verbose=0, timeout=1)
                    if reply is None:
                        # No reply
                        break
                    elif reply.type == 3:
                        # On a atteint notre destination!
                        iphops[live_host.ip] = hops
                        break

        for ip, hops in iphops.items():
            print("{0:s} is {1:d} hops away!".format(ip, hops))

    def pretty_print_ips(self):
        for network, live_hosts in self.live_network_hosts.items():
            for live_host in live_hosts:
                print("{0:20s} {1:s}".format(live_host.ip, live_host.mac))

    def scan_live_hosts_for_opened_ports(self):
        count = sum(len(v) for v in self.live_network_hosts.values())
        results = [None] * count
        threads = []
        for network, live_hosts in self.live_network_hosts.items():
            for live_host in live_hosts:
                t = PortScanThread(portlist=topports, tid=len(threads), target=live_host, results=results)
                t.start()
                threads.append(t)

        for thread in threads:
            thread.join()

        for r in results:
            if r:
                print(r)


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
