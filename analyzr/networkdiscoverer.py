"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
from typing import List

import netaddr
from scapy.all import *
from scapy.layers.inet import traceroute

from analyzr.core.entities import NetworkNode
from analyzr.networktool import NetworkToolFacade
from analyzr.utils.useful import pprint_table

logger = logging.getLogger(__name__)


def discover():
    pass


class NetworkDiscoverer():
    # Taken from netdiscover main.c
    # https://sourceforge.net/p/netdiscover/code/115/tree/trunk/src/main.c
    common_networks = [
        netaddr.IPNetwork("192.168.0.0/16"),
        netaddr.IPNetwork("172.16.0.0/12"),
        netaddr.IPNetwork("10.0.0.0/8")]

    # "10.0.0.0/8"

    def __init__(self, network_tool: NetworkToolFacade, fingerprinters: list):
        self.network_tool = network_tool
        self.discovered_network_hosts = defaultdict(
            set)  # (network --> set(NetworkNode, NetworkNode, NetworkNode, ...))

    def discover(self, network_ranges: list = None):
        """
        Scans specified network ranges to find live hosts. If no networks given, a default list is used.

        Returns True if any hosts were found. False if otherwise.
        """

        def scan(net: netaddr.IPNetwork):
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
                scan(net)
            else:
                # If bigger than a /16 we split the network into subnetworks to avoid flooding the network with ARP
                # packets
                logger.info("Splitting {0:s} into /16 subnets to avoid sending too many ARP packets.".format(str(net)))
                for subnet in net.subnet(16):
                    scan(subnet)

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
        all_nodes = []
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:
                all_nodes.append(network_node)

        if all_nodes:
            logger.info("Drawing network graph...")
            #res, unans = traceroute([str(nn.ip) for nn in all_nodes], dport=[80, 443], maxttl=20, retry=-2)
            #res, unans = traceroute("google.com", dport=[80, 443], maxttl=20, retry=-2)

            import matplotlib.pyplot as plt
            import datetime
            import networkx as nx

            getsrcdst = lambda x: (x['IP'].src, x['IP'].dst)

            # res.conversations(draw=True, getsrcdst=lambda x:(x['IP'].src + "\n" + resolve_ip(x['IP'].src), x['IP'].dst + "\n" + resolve_ip(x['IP'].dst)))
            # res.conversations(draw=True,
            #                   edge_color='blue',
            #                   # NetworkX stuff
            #                   node_size=1600,
            #                   node_color='blue',
            #                   font_size=12,
            #                   alpha=0.3,
            #                   font_family='sans-serif')

            nodes = {}
            current_host_info = self.network_tool.host_information
            host_ip = current_host_info.ip

            # on bâti un dictionnaire du genre:
            # {'172.16.2.235': '192.168.1.1', '192.168.1.1': '167.1.2.4', '167.1.2.4': '10.0.0.4', '10.0.0.4': '204.3.32.21'}
            for nn in all_nodes:  # type: NetworkNode
                if not nn.hops:
                    continue

                next_hop = nn.hops[0]
                nodes[host_ip] = next_hop

                for i in range(1, len(nn.hops)):
                    ip = nn.hops[i]
                    nodes[next_hop] = ip
                    next_hop = ip

            val_map = {}
            for nn in all_nodes:
                val_map[str(nn.ip)] = 0.5714285714285714

            gr = nx.Graph()

            for s, d in nodes.items():
                if s not in gr:
                    gr.add_node(s)
                if d not in gr:
                    gr.add_node(d)
                gr.add_edge(s, d)

            values = [val_map.get(node, 0.25) for node in gr.nodes()]
            nx.draw(gr, cmap=plt.get_cmap('jet'), node_color=values, with_labels=True)

            # nx.draw(gr,
            #         with_labels=True,
            #         edge_color='blue',
            #         node_size=1600,
            #         node_color='blue',
            #         font_size=12,
            #         alpha=0.3,
            #         font_family='sans-serif')

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
        for network, network_nodes in self.discovered_network_hosts.items():
            print("Live hosts in network {0:s}".format(str(network)))

            header_labels = ["IP", "MAC", "Host", "Hops", "Opened Ports", "Closed Ports", "Possible Fingerprints"]
            table_data = []

            for nn in network_nodes:
                table_data.append([str(nn.ip or "Unknown IP"),
                                   str(nn.mac or "Unknown MAC"),
                                   nn.host or "Unknown Host",
                                   "{hops} ({nb_hops})".format(hops=" --> ".join(hop for hop in nn.hops),
                                                               nb_hops=len(nn.hops)),
                                   str(nn.opened_ports),
                                   str(nn.closed_ports),
                                   str(nn.possible_fingerprints or "Unknown")])

            pprint_table(table_data, header_labels=header_labels, blank_line_after_header=True, out=sys.stdout)

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
