import threading
from queue import Queue

from netaddr import EUI, IPAddress
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.layers.l2 import arping
from scapy.sendrecv import sr1

from analyzr.core import config
from analyzr.core.entities import NetworkNode
from analyzr.networkdiscovery.scanner import Scanner
from analyzr.topports import topports
from analyzr.utils.network import resolve_ip, TCPFlag, ScapyTCPFlag

logger = logging.getLogger(__name__)


class ArpPing(Scanner):
    def __init__(self):
        super(ArpPing, self).__init__(name="Arp Ping Scanner")

    def scan(self):
        try:
            for interface, network in config.interfaces_networks.items():
                if not network.is_private():
                    self.logger.info(
                        "Skipping arp ping scan on network {0:s} because it's a public network".format(str(network)))
                    continue

                self.logger.info("Executing arp ping scan on network {0:s}...".format(str(network)))
                discovered_hosts = set()
                ans, unans = arping(str(network), iface=interface, timeout=1, verbose=False)
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

        self.logger.info("Arp ping scan done. Found %d unique hosts.", self.number_of_hosts_found)


class ICMPPing(Scanner):
    def __init__(self):
        super(ICMPPing, self).__init__("ICMP Ping Scanner")

    def scan(self):
        try:
            for interface, network in config.interfaces_networks.items():
                if network.is_private() and not config.scan_local_network_as_public:
                    self.logger.info(
                        "Skipping ICMP ping scan on network {0:s} because it's a private network.".format(str(network)))
                    continue

                self.logger.info("Executing ICMP ping scan on network {0:s}...".format(str(network)))
                discovered_hosts = set()

                ips_queue = Queue(network.size)
                for thread_id in range(config.num_ping_threads):
                    t = threading.Thread(
                        target=self._ping,
                        args=(ips_queue, interface, discovered_hosts,),
                        name='worker-{}'.format(thread_id),
                        daemon=True
                    )
                    t.start()

                # populate the queue
                [ips_queue.put(host_ip) for host_ip in network.iter_hosts()]

                self.logger.debug('*** main thread waiting')
                ips_queue.join()

                self.logger.debug(u"Got {0:d} answers.".format(len(discovered_hosts)))

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("ICMP ping scan done. Found %d unique hosts.", self.number_of_hosts_found)

    def _ping(self, hosts: Queue, interface: str, results: set):
        self.logger.debug("{}: Starting ICMP ping thread.".format(threading.current_thread().name))
        while True:
            ip = hosts.get()  # type: IPAddress
            ip_str = str(ip)

            res = sr1(IP(dst=ip_str) / ICMP(), iface=interface, timeout=0.1, verbose=False)
            if res:
                node = NetworkNode()
                node.ip = ip
                node.mac = EUI(res.src)
                node.host = resolve_ip(res[IP].src)
                results.add(node)

            hosts.task_done()


class TCPSYNPing(Scanner):
    def __init__(self):
        super(TCPSYNPing, self).__init__("TCP SYN Ping Scanner")
        if config.fastTCP:
            self.portstoscan = [80]
        else:
            self.portstoscan = topports

    def scan(self):
        """
        Attempts to identify if a host exists by sending a TCP SYN packet to a port. If we receive a SYN/ACK or a RST
        packet we know the host exists and we stop searching. This is not a port scanner. This does not find opened
        ports (it stops to search at the first sign that the host exists).
        """
        try:
            for interface, network in config.interfaces_networks.items():
                if network.is_private() and not config.scan_local_network_as_public:
                    self.logger.info(
                        "Skipping TCP ACK Ping on {0:s} because it's a private network.".format(str(network)))
                    continue

                if config.fastTCP:
                    self.logger.info("Executing TCP SYN ping scan (fast version) on {0:s}...".format(str(network)))
                else:
                    self.logger.info("Executing TCP SYN ping scan (slow version) on {0:s}...".format(str(network)))

                self.logger.info("Scanning ports %s.", str(self.portstoscan).strip("[]"))

                discovered_hosts = set()

                ips_queue = Queue(network.size)
                for thread_nbr in range(config.num_ping_threads):
                    t = threading.Thread(
                        target=self._port_ping,
                        args=(ips_queue, interface, discovered_hosts,),
                        name='worker-{}'.format(thread_nbr),
                        daemon=True
                    )
                    t.start()

                # populate the queue
                [ips_queue.put(host_ip) for host_ip in network.iter_hosts()]

                self.logger.debug('*** main thread waiting')
                ips_queue.join()

                self.logger.debug(u"Got {0:d} answers.".format(len(discovered_hosts)))

                self.scan_results[network] = discovered_hosts
        except socket.error as e:
            if e.errno == socket.errno.EPERM:  # Operation not permitted
                self.logger.error("%s. Did you run as root?", e.strerror)
            else:
                raise

        self.logger.info("TCP SYN ping scan done. Found %d unique hosts.", self.number_of_hosts_found)

    def _port_ping(self, hosts: Queue, interface: str, results: set):
        self.logger.debug("{}: Starting TCP SYN ping thread.".format(threading.current_thread().name))

        while True:
            ip = hosts.get()  # type: IPAddress
            ip_str = str(ip)

            # Send SYN with random Src Port for each Dst port
            for dstPort in self.portstoscan:
                srcPort = random.randint(1025, 65534)
                resp = sr1(IP(dst=ip_str) / TCP(sport=srcPort, dport=dstPort, flags=ScapyTCPFlag.SYN), timeout=1,
                           verbose=False,
                           iface=interface)
                if resp and resp.haslayer(TCP):
                    if resp[TCP].flags == (TCPFlag.SYN | TCPFlag.ACK) or resp[TCP].flags == (TCPFlag.RST | TCPFlag.ACK):
                        # Send Reset packet (RST)
                        send(IP(dst=ip_str) / TCP(sport=srcPort, dport=dstPort, flags=ScapyTCPFlag.RST),
                             iface=interface, verbose=False)

                        # We know the port is closed or opened (we got a response), so we deduce that the host exists
                        node = NetworkNode()
                        node.ip = ip
                        node.mac = EUI(resp.src)
                        node.host = resolve_ip(resp[IP].src)
                        results.add(node)

                        self.logger.debug(
                            "Found a live host by pinging port {port_nbr}: {live_host}.".format(port_nbr=dstPort,
                                                                                                live_host=str(node)))

                        # We don't need to test the other ports. We know the host exists.
                        break

            hosts.task_done()
