"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""

from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, traceroute

from analyzr.core.entities import NetworkNode
from analyzr.portscanthread import PortScanThread
from analyzr.topports import topports
from analyzr.utils.network import ScapyTCPFlag

logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    def __init__(self, scanners: list, fingerprinters: list):
        self.scanners = scanners
        self.fingerprinters = fingerprinters
        self.host_ip_address = ""
        self.live_network_hosts = defaultdict(set)  # (network --> set(NetworkNode, NetworkNode, NetworkNode, ...))

    def discover(self):
        logger.info("Starting host discovery...")
        for scanner in self.scanners:
            scanner.scan()
            self._add_results(scanner.scan_results)

        logger.info("Discovery done.")

        logger.info("The scan found these hosts: ")
        self.pretty_print_ips()

        logger.info("Trying to identify fingerprints of live hosts...")
        self.identify_fingerprints()
        logger.info("...done.")

        logger.info("Drawing network graph...")
        self.traceroute_graph()
        logger.info("...Done")

        self.pretty_print_ips()

    def _add_results(self, scan_results: dict):
        for network, network_nodes in scan_results.items():
            self.live_network_hosts[network].update(network_nodes)

    def identify_fingerprints(self):
        responses = dict()
        for network, network_nodes in self.live_network_hosts.items():
            for network_node in network_nodes:
                srcPort = random.randint(1025, 65534)
                resp = sr1(IP(dst=str(network_node.ip)) / TCP(sport=srcPort, dport=topports, flags=ScapyTCPFlag.SYN),
                           timeout=1, verbose=0)
                if resp:
                    responses[network_node] = resp

        for fingerprinter in self.fingerprinters:  # type: fingerprinter
            for network_node, resp in responses.items():
                os = fingerprinter.identify_os_from_pkt(resp)
                if os:
                    network_node.possible_fingerprints |= os

    def traceroute_graph(self):
        all_ips = []
        for network, network_nodes in self.live_network_hosts.items():
            for network_node in network_nodes:
                all_ips.append(str(network_node.ip))

        if all_ips:
            res, unans = traceroute(all_ips, dport=[80, 443], maxttl=20, retry=-2)
            if res:
                import matplotlib.pyplot as plt
                import datetime
                import networkx as nx

                # res.conversations(draw=True, getsrcdst=lambda x:(x['IP'].src + "\n" + resolve_ip(x['IP'].src), x['IP'].dst + "\n" + resolve_ip(x['IP'].dst)))
                # res.conversations(draw=True,
                #                   edge_color='blue',
                #                   # NetworkX stuff
                #                   node_size=1600,
                #                   node_color='blue',
                #                   font_size=12,
                #                   alpha=0.3,
                #                   font_family='sans-serif')

                gr = res.conversations(draw=False)

                nx.draw(gr,
                        with_labels=True,
                        edge_color='blue',
                        node_size=1600,
                        node_color='blue',
                        font_size=12,
                        alpha=0.3,
                        font_family='sans-serif')

                # filename = get_next_file_path(folder=os.path.abspath(os.path.join("graphs")),
                #                              base_filename="network_graph.png")

                filename = "network_graph_" + datetime.datetime.now().strftime("%Y_%m_%d__%H%M%S") + ".png"
                fullpath = os.path.abspath(os.path.join("graphs", filename))
                plt.savefig(fullpath)
                logger.info("Created network graph at path: {0:s}".format(fullpath))

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
            print(NetworkNode.str_template.format("IP", "MAC", "Host", "Opened Ports", "Possible fingerprints"))
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
