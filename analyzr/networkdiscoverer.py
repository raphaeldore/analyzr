"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
import errno

from netaddr import IPAddress, EUI
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import arping

from .core.entities import NetworkNode
from .portscanthread import PortScanThread
from .topports import topports


logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    def __init__(self, scanners : list()):
        self.scanners = scanners
        self.host_ip_address = ""
        self.live_network_hosts = dict()  # (network --> (ip --> mac, ip --> mac, ip --> mac))

    def discover(self):
        for scanner in self.scanners:
            scanner.scan()

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

    def scan_and_find_network_nodes_on_networks(self, timeout=1):
        try:
            for interface, network in self.networks_interfaces.items():
                ans, unans = scapy.layers.l2.arping(str(network), iface=interface, timeout=timeout, verbose=False)
                for s, r in ans.res:
                    node = NetworkNode()
                    node.ip = IPAddress(r[ARP].psrc)
                    node.mac = EUI(r[Ether].src)
                    node.host = self.resolve(r[ARP].psrc)
                    self.live_network_hosts.setdefault(network, []).append(node)

                # On sniff le réseau pendant quelques secondes pour trouver des hôtes additionnels
                self.passive_network_scan(network)
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

    def passive_network_scan(self, network):
        logger.debug("Sniffing network traffic for more hosts.")
        new_hosts_count = 0
        ans = sniff(timeout=10)
        logger.debug("Analyzing traffic.")
        for i in ans:
            if IP in i:
                src = IPAddress(i[IP].src)
                dst = IPAddress(i[IP].dst)
            elif ARP in i:
                src = IPAddress(i[ARP].psrc)
                dst = IPAddress(i[ARP].pdst)
            else:
                continue

            if src in network.cidr and not [network_node for network_node in self.live_network_hosts[network]
                                            if src == network_node.ip]:
                new_hosts_count += 1
                host = self.resolve(str(src))
                self.live_network_hosts.setdefault(network, []).append(NetworkNode(src, EUI(i.src), host))

            if dst in network.cidr and not [network_node for network_node in self.live_network_hosts[network]
                                            if dst == network_node.ip] and i.dst != 'ff:ff:ff:ff:ff:ff':
                host = self.resolve(str(src))
                new_hosts_count += 1
                self.live_network_hosts.setdefault(network, []).append(NetworkNode(dst, EUI(i.dst), host))

        logger.debug("Passive scan found {0:d} new hosts.".format(new_hosts_count))

    def resolve(self, ip):
        """rdns with a timeout"""
        socket.setdefaulttimeout(2)
        try:
            host = socket.gethostbyaddr(ip)
        except:
            host = None
        if not host is None:
            host = host[0]
        return host

    def find_hops(self):
        iphops = dict()
        for network, network_nodes in self.live_network_hosts.items():
            for network_node in network_nodes:
                for hops in range(1, 28):
                    reply = sr1(IP(dst=str(network_node.ip), ttl=hops) / UDP(dport=40000), verbose=0, timeout=1)
                    if reply is None:
                        # No reply
                        break
                    elif reply.type == 3:
                        # On a atteint notre destination!
                        iphops[network_node.ip] = hops
                        break

        for ip, hops in iphops.items():
            print("{0:s} is {1:d} hops away!".format(str(ip), hops))

    def pretty_print_ips(self):
        for network, network_nodes in self.live_network_hosts.items():
            print("Live hosts in network {0:s}".format(str(network)))
            for network_node in network_nodes:
                print(u'\t{0:20s}{1:20s}{2:20s}'.format(str(network_node.ip),
                                                        str(network_node.mac),
                                                        str(network_node.host)))

    def scan_found_network_nodes_for_opened_ports(self):
        count = sum(len(v) for v in self.live_network_hosts.values())
        results = [None] * count
        threads = []
        for network, network_nodes in self.live_network_hosts.items():
            for network_node in network_nodes:
                t = PortScanThread(portlist=topports, tid=len(threads), target=network_node, results=results)
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
