import random
import socket

import errno
import scapy
from netaddr import IPAddress, EUI
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sr1, sr

from analyzr import topports
from analyzr.core.entities import NetworkNode
from analyzr.networkdiscovery.scanner import Scanner
from analyzr.utils.network import resolve_ip


class ArpPing(Scanner):
    def __init__(self):
        super(ArpPing, self).__init__()

    def scan(self):
        try:
            for interface, network in self.config["networks_interfaces"]:
                discovered_hosts = set()
                ans, unans = scapy.layers.l2.arping(str(network), iface=interface, timeout=1, verbose=False)
                for s, r in ans.res:
                    node = NetworkNode()
                    node.ip = IPAddress(r[ARP].psrc)
                    node.mac = EUI(r[Ether].src)
                    node.host = resolve_ip(r[ARP].psrc)
                    discovered_hosts.add(node)

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise


class PortPing(Scanner):
    def __init__(self):
        super(PortPing, self).__init__()

    def scan(self):
        try:
            for interface, network in self.config["networks_interfaces"]:
                discovered_hosts = set()
                # Toutes les addresses possibles du réseau
                for addr in list(network):
                    if addr == network.broadcast:
                        continue

                    discovered_host = self._portScan(str(addr), topports, network, interface)
                    if discovered_host:
                        discovered_hosts.add(discovered_host)

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

    def _portScan(self, host, ports, network, interface):
        # Send SYN with random Src Port for each Dst port
        for dstPort in ports:
            srcPort = random.randint(1025, 65534)
            resp = sr1(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="S"), timeout=1, verbose=0,
                       iface=interface)
            if resp is None:
                self.logger.info(host + ":" + str(dstPort) + " is filtered (silently dropped).")
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12 or resp.getlayer(TCP).flags == 0x14:
                    send_rst = sr(IP(dst=host) / TCP(sport=srcPort, dport=dstPort, flags="R"), timeout=1, verbose=0)
                    # We know the port is closed or opened (we got a response), so we deduce that the host exists
                    node = NetworkNode()
                    node.ip = IPAddress(resp[IP].src)
                    node.mac = EUI(resp[Ether].src)
                    node.host = resolve_ip(resp[Ether].src)
                    return NetworkNode
                elif resp.haslayer(ICMP):
                    if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        pass
                        # Impossible de savoir si le host existe
                        #self.logger.info(host + ":" + str(dstPort) + " is filtered (silently dropped).")

        return None
