"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
from typing import List

import netaddr
from scapy.all import *
from texttable import Texttable

from analyzr.core.entities import NetworkNode
from analyzr.networktool import NetworkToolFacade

logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    # Adapted from netdiscover main.c
    # https://sourceforge.net/p/netdiscover/code/115/tree/trunk/src/main.c
    # And improved by using netaddr.
    common_networks = [
        netaddr.IPNetwork("192.168.0.0/16"),
        netaddr.IPNetwork("172.16.0.0/12"),
        netaddr.IPNetwork("10.0.0.0/8")]

    # "10.0.0.0/8"

    def __init__(self, network_tool: NetworkToolFacade, fingerprinters: list):
        self.network_tool = network_tool
        self.discovered_network_hosts = defaultdict(
            set)  # (network --> set(NetworkNode, NetworkNode, NetworkNode, ...))

    def discover(self, network_ranges: List[str] = None):
        """
        Scans specified network ranges to find live hosts. If no networks given, a default list is used.

        Returns True if any hosts were found. False if otherwise.
        """

        def _discover(net: netaddr.IPNetwork):
            logger.debug("Starting host discovery on network {network}...".format(network=net))
            results = self.network_tool.arp_discover_hosts(network=str(net), timeout=10)

            if results:
                logger.info("Found {nb_found_hosts} hosts in {network}.".format(nb_found_hosts=len(results),
                                                                                network=net))

                for result in results:
                    network_node = NetworkNode(ip=netaddr.IPAddress(result.ip), mac=netaddr.EUI(result.mac))
                    self.discovered_network_hosts[net].add(network_node)
            else:
                logger.info("No hosts found on {network}.".format(network=net))

        logger.info("Starting host discovery...")

        if network_ranges:
            networks_to_scan = [netaddr.IPNetwork(net_to_scan) for net_to_scan in network_ranges]
        else:
            networks_to_scan = self.common_networks

        for net in networks_to_scan:
            if net.prefixlen >= 16:
                _discover(net)
            else:
                # If bigger than a /16 we split the network into subnetworks to avoid flooding the network with ARP
                # packets
                logger.info("Splitting {0:s} into /16 subnets to avoid sending too many ARP packets.".format(str(net)))
                for subnet in net.subnet(16):
                    _discover(subnet)

        logger.info("Discovery done.")

        if self.discovered_network_hosts:
            return True

        return False

    # TODO: This is bad and you should feel bad
    # def identify_fingerprints(self):
    #     responses = dict()
    #     for network, network_nodes in self.discovered_network_hosts.items():
    #         for network_node in network_nodes:
    #             srcPort = random.randint(1025, 65534)
    #             resp = sr1(IP(dst=str(network_node.ip)) / TCP(sport=srcPort, dport=topports, flags=ScapyTCPFlag.SYN),
    #                        timeout=1, verbose=0)
    #             if resp:
    #                 responses[network_node] = resp
    #
    #     for fingerprinter in self.fingerprinters:  # type: fingerprinter
    #         for network_node, resp in responses.items():
    #             os = fingerprinter.identify_os_from_pkt(resp)
    #             if os:
    #                 network_node.possible_fingerprints |= os

    def make_network_graph(self):
        hosts = set()
        devices = set()

        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:
                hosts.add(network_node)

        if hosts:
            logger.info("Drawing network graph...")

            import matplotlib.pyplot as plt
            import datetime
            import networkx as nx

            nodes = set()
            current_host_info = self.network_tool.host_information
            host_ip = current_host_info.ip
            lone_nodes = set()

            # on bâti un set du genre:
            #
            #      source        destination
            # {('172.16.2.243', '172.16.2.1'), ('172.16.2.243', '172.16.2.8')}
            for nn in hosts:  # type: NetworkNode
                if not nn.hops:
                    lone_nodes.add(str(nn.ip))
                    continue

                next_hop = nn.hops[0]
                nodes.add((host_ip, next_hop))

                for i in range(1, len(nn.hops)):
                    ip = nn.hops[i]
                    nodes.add((next_hop, ip))
                    next_hop = ip

            val_map = {}
            for nn in hosts:
                # TODO:
                # if nn.type != "host":
                #     continue

                val_map[str(nn.ip)] = 0.5714285714285714

            gr = nx.Graph()

            for s, d in nodes:
                if s not in gr:
                    gr.add_node(s)
                if d not in gr:
                    gr.add_node(d)
                gr.add_edge(s, d)

            for s in lone_nodes:
                gr.add_node(s)

            values = [val_map.get(node, 0.25) for node in gr.nodes()]

            plt.figure(figsize=(20, 20))
            plt.rcParams.update({'axes.titlesize': 'large'})
            plt.title("Scan Topology", fontsize=20)

            nx.draw(gr,
                    with_labels=True,
                    edge_color='blue',
                    node_size=7000,
                    node_color=values,
                    font_size=12,
                    alpha=0.3,
                    font_family='sans-serif',
                    cmap=plt.get_cmap('jet'),
                    )

            # filename = get_next_file_path(folder=os.path.abspath(os.path.join("graphs")),
            #                              base_filename="network_graph.png")

            filename = "network_graph_" + datetime.datetime.now().strftime("%Y_%m_%d__%H%M%S") + ".png"
            fullpath = os.path.abspath(os.path.join("..", "graphs", filename))
            plt.savefig(fullpath)
            logger.info("Created network graph ({0:s})".format(fullpath))

    def find_hops(self):
        logger.info("Attempting to find hops needed to reach discovered hosts...")
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:  # type: NetworkNode
                logger.debug("Finding hops for {ip}".format(ip=str(network_node.ip)))
                network_node.hops = self.network_tool.route_to_target(str(network_node.ip))
                logger.debug("Route to get to {ip} : {route}".format(ip=str(network_node.ip),
                                                                     route=" --> ".join(network_node.hops)))

        logger.info("Hops discovery done.")

    def pretty_print_ips(self):
        header_labels = ["IP", "MAC", "Host", "Hops", "Opened Ports", "Closed Ports", "Possible Fingerprints"]
        table = Texttable(max_width=230)

        # We only want the header and the horizontal lines
        table.set_deco(Texttable.HEADER | Texttable.HLINES)

        # All columns are of type str
        table.set_cols_dtype(["t"] * len(header_labels))

        # All columns left align
        table.set_cols_align(["l"] * len(header_labels))

        table.set_cols_width([15, 17, 30, 58, 30, 30, 50])

        for network, network_nodes in self.discovered_network_hosts.items():
            table.header(header_labels)

            print("Live hosts in network {0:s}".format(str(network)))

            for nn in network_nodes:
                table.add_row([str(nn.ip or "Unknown IP"),
                               str(nn.mac or "Unknown MAC"),
                               nn.host or "Unknown Host",
                               "{hops} ({nb_hops})".format(hops=" --> ".join(hop for hop in nn.hops),
                                                           nb_hops=len(nn.hops)),
                               str(nn.opened_ports),
                               str(nn.closed_ports),
                               str(nn.possible_fingerprints or "Unknown")])

            print(table.draw())
            table.reset()

    def scan_found_network_nodes_for_opened_ports(self, ports_to_scan: List[int]):
        logger.info("Checking founds hosts for opened ports...")
        logger.info("Scanning ports %s.", str(ports_to_scan).strip("[]"))
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:  # type: NetworkNode
                opened_ports, closed_ports = self.network_tool.tcp_port_scan(str(network_node.ip), ports_to_scan)

                logger.debug("{0:s} has these ports opened: {1:s}".format(str(network_node.ip),
                                                                          str(opened_ports).strip("[]")))
                logger.debug("{0:s} has these ports closed: {1:s}".format(str(network_node.ip),
                                                                          str(closed_ports).strip("[]")))
                network_node.opened_ports = opened_ports
                network_node.closed_ports = closed_ports
