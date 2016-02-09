"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""

from scapy.all import *
from scapy.layers.inet import IP, UDP

from .portscanthread import PortScanThread
from .topports import topports

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    def __init__(self, scanners: list()):
        self.scanners = scanners
        self.host_ip_address = ""
        self.live_network_hosts = dict()  # (network --> set(NetworkNode, NetworkNode, NetworkNode, ...))

    def discover(self):
        for scanner in self.scanners:
            scanner.scan()

        self.combine_results()

    def combine_results(self):
        for scanner in self.scanners:
            for network, network_nodes in scanner.scan_results.items():
                tmp = self.live_network_hosts.setdefault(network, set())
                tmp.update(network_nodes)

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
