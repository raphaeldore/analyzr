"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""

import netaddr
from scapy.all import *
from scapy.layers.inet import IP, UDP, traceroute

from analyzr.core.entities import NetworkNode
from analyzr.networktool import NetworkToolFacade

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
        all_ips = []
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:
                all_ips.append(str(network_node.ip))

        if all_ips:
            logger.info("Drawing network graph...")
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
                fullpath = os.path.abspath(os.path.join("..", "graphs", filename))
                plt.savefig(fullpath)
                logger.info("Created network graph ({0:s})".format(fullpath))

    def find_hops(self):
        iphops = dict()
        for network, network_nodes in self.discovered_network_hosts.items():
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
        for network, network_nodes in self.discovered_network_hosts.items():
            print("Live hosts in network {0:s}".format(str(network)))
            print(NetworkNode.str_template.format("IP", "MAC", "Host", "Opened Ports", "Possible fingerprints"))
            for network_node in network_nodes:
                print(network_node)

    def scan_found_network_nodes_for_opened_ports(self, ports_to_scan: list):
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
