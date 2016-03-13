import math
import socket
import struct

from netaddr import IPNetwork, IPAddress
from scapy.all import conf


def long2netmask(arg):
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def ip2int(addr: bytes):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr: int):
    return socket.inet_ntoa(struct.pack("!I", addr))


def to_CIDR_notation(bytes_network, bytes_netmask) -> str:
    network = int2ip(bytes_network)
    netmask = long2netmask(bytes_netmask)

    net = u"{0:s}/{1:d}".format(network, netmask)

    if netmask < 16:
        return None

    return net


def get_local_interfaces_networks() -> (dict, dict):
    interfaces_networks = dict()
    networks_ips = dict()

    for network, netmask, gateway, interface, address in conf.route.routes:

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        cidr = to_CIDR_notation(network, netmask)

        if not cidr:
            continue

        ip_network = IPNetwork(cidr)

        if ip_network is None:
            continue

        interfaces_networks[interface] = ip_network
        networks_ips[ip_network] = IPAddress(address)

    return interfaces_networks, networks_ips


def resolve_ip(ip, timeout: int = 1):
    """rdns with a timeout
    :param timeout: Timeout in secondes before calling quits on resolving the hostname.
    """
    socket.setdefaulttimeout(timeout)
    try:
        host = socket.gethostbyaddr(ip)
    except:
        host = None
    if host is not None:
        host = host[0]
    return host
