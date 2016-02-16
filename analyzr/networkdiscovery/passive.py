import socket

import errno
from netaddr import IPAddress, EUI

from analyzr.core import config
from analyzr.core.entities import NetworkNode
from analyzr.networkdiscovery.scanner import Scanner
from analyzr.utils.network import resolve_ip


class SnifferDiscovery(Scanner):
    def __init__(self):
        super(SnifferDiscovery, self).__init__("Passive sniffer")

    def scan(self):
        try:
            from scapy.sendrecv import sniff

            self.logger.info("Executing passive sniffer scan...")
            for interface, network in config.interfaces_networks.items():
                discovered_hosts = set()
                ans = sniff(timeout=config.snifferdiscovery_timeout, iface=interface)
                for i in ans:
                    from scapy.layers.inet import IP
                    from scapy.layers.l2 import ARP
                    if IP in i:
                        src = IPAddress(i[IP].src)
                        dst = IPAddress(i[IP].dst)
                    elif ARP in i:
                        src = IPAddress(i[ARP].psrc)
                        dst = IPAddress(i[ARP].pdst)
                    else:
                        continue

                    if src in network.cidr and src not in discovered_hosts:
                        host = resolve_ip(str(src))
                        discovered_hosts.add(NetworkNode(src, EUI(i.src), host))

                    if dst in network.cidr and dst not in discovered_hosts and i.dst != 'ff:ff:ff:ff:ff:ff':
                        host = resolve_ip(str(src))
                        discovered_hosts.add(NetworkNode(dst, EUI(i.dst), host))

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("Passive sniffer scan done. Found %d unique hosts.", self.number_of_hosts_found)
