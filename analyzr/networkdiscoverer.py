"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""

from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP

from fingerprints import fingerprinter
from utils.network import ScapyTCPFlag
from analyzr.portscanthread import PortScanThread
from analyzr.topports import topports

logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    def __init__(self, scanners: list, fingerprinters: list):
        self.scanners = scanners
        self.fingerprinters = fingerprinters
        self.host_ip_address = ""
        self.live_network_hosts = dict()  # (network --> set(NetworkNode, NetworkNode, NetworkNode, ...))

    def discover(self):
        logger.info("Starting host discovery...")
        for scanner in self.scanners:
            scanner.scan()

        logger.info("Discovery done.")
        self.combine_results()

        logger.info("Trying to identify fingerprints of live hosts...")
        self.identify_fingerprints()
        logger.info("...done.")

    def combine_results(self):
        for scanner in self.scanners:
            for network, network_nodes in scanner.scan_results.items():
                tmp = self.live_network_hosts.setdefault(network, set())
                tmp.update(network_nodes)

    def identify_fingerprints(self):
        responses = dict()
        for network, network_nodes in self.live_network_hosts.items():
            for network_node in network_nodes:
                srcPort = random.randint(1025, 65534)
                resp = sr1(IP(dst=str(network_node.ip)) / TCP(sport=srcPort, dport=topports, flags=ScapyTCPFlag.SYN), timeout=1, verbose=0)
                if resp:
                    responses[network_node] = resp

        for fingerprinter in self.fingerprinters: # type: fingerprinter
            for network_node, resp in responses.items():
                os = fingerprinter.identify_os_from_pkt(resp)
                if os:
                    network_node.possible_fingerprints.add(os)

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
                print(network_node)

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
