"""
analyzr.NetworkScanner
~~~~~~~~~~~~~~~

This modules allows to scan the network of the current host..
"""
import logging
import os
from collections import defaultdict

import netaddr
from texttable import Texttable

from analyzr import constants
from analyzr.core import NetworkNode
from analyzr.networktool import NetworkToolFacade
from analyzr.utils.file import make_sure_path_exists

logger = logging.getLogger(__name__)


class NetworkDiscoverer():
    private_ipv4_space = [
        netaddr.IPNetwork("192.168.0.0/16"),
        netaddr.IPNetwork("172.16.0.0/12"),
        netaddr.IPNetwork("10.0.0.0/8")]

    def __init__(self, network_tool: NetworkToolFacade, config: dict):
        """

        :param network_tool: An instance of the NetworkToolFacade class. This will be used to execute the different
         discovery steps.

        :param config: A dictionary of configurations. Dictionary accepts these configs:

            :param config["networks"]: a List[str] of networks in CIDR notation. This is the networks we will try to find hosts on.
                Ex: ["192.168.1.0/24", "10.0.0.0/8"].

            :param config["ports"]: a List[int] of ports to scan.
                Ex: [22, 23, 80, 443]

            :param config["discovery_mode"]: "active", "passive" or "both". Determine the discovery method. Active sends arp,
            TCP, whatever requests. It is not subtle at all. Passive listens to network traffic and attemps to find hosts
            in the network. Both does both.


        """
        self.network_tool = network_tool

        if "ports" in config and config["ports"]:
            self.ports_to_scan = config["ports"]
        else:
            logger.warning("No ports to scan given. Will scan default popular ports ({ports})."
                           .format(ports=", ".join(map(str, constants.topports))))
            self.ports_to_scan = constants.topports

        if "networks" in config and config["networks"]:
            self.networks_to_scan = [netaddr.IPNetwork(net_to_scan) for net_to_scan in config["networks"]]
        else:
            logger.warning("No networks to scan given. Will scan all private IPV4 space ({ipv4space})."
                           .format(ipv4space=', '.join(map(str, self.private_ipv4_space))))
            self.networks_to_scan = self.private_ipv4_space

        if "discovery_mode" in config and config["discovery_mode"]:
            self.discovery_mode = config["discovery_mode"]
        else:
            logger.warning("No discovery mode given. Assuming active and passive discovery modes.")
            self.discovery_mode = "all"

        # {netaddr.IPNetwork : {NetworkNode, NetworkNode, NetworkNode, ...}, netaddr.IPNetwork: {...}}
        self.discovered_network_hosts = defaultdict(set)

    def discover(self):
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

        for net in self.networks_to_scan:
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
    def identify_fingerprints(self):
        logger.info("Trying to identify found hosts fingerprints...")
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:  # type: NetworkNode
                possible_fingerprints = self.network_tool.identify_host_os(str(network_node.ip))
                if possible_fingerprints:
                    network_node.possible_fingerprints |= possible_fingerprints

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

            graphs_folder_path = os.path.abspath(os.path.join("..", "graphs"))
            make_sure_path_exists(graphs_folder_path)

            graph_save_path = os.path.join(graphs_folder_path, filename)
            plt.savefig(graph_save_path)
            logger.info("Created network graph ({0:s})".format(graph_save_path))

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
        header_labels = ["IP", "MAC", "Hostname", "Hops", "Opened Ports", "Closed Ports", "Possible Fingerprints"]
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

            sorted_network_nodes = sorted(network_nodes, key=lambda nn: nn.ip.value)
            for nn in sorted_network_nodes:
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

    def scan_found_network_nodes_for_opened_ports(self):
        logger.info("Checking founds hosts for opened ports...")
        logger.info("Scanning ports %s.", str(self.ports_to_scan).strip("[]"))
        for network, network_nodes in self.discovered_network_hosts.items():
            for network_node in network_nodes:  # type: NetworkNode
                opened_ports, closed_ports = self.network_tool.tcp_port_scan(str(network_node.ip), self.ports_to_scan)

                logger.debug("{0:s} has these ports opened: {1:s}".format(str(network_node.ip),
                                                                          str(opened_ports).strip("[]")))
                logger.debug("{0:s} has these ports closed: {1:s}".format(str(network_node.ip),
                                                                          str(closed_ports).strip("[]")))
                network_node.opened_ports = opened_ports
                network_node.closed_ports = closed_ports
