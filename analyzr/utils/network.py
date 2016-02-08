import math
import socket
import struct


def long2netmask(arg):
    if arg <= 0 or arg >= 0xFFFFFFFF:
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def ip2int(addr : bytes):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr : int):
    return socket.inet_ntoa(struct.pack("!I", addr))


def to_CIDR_notation(bytes_network, bytes_netmask) -> str:
    network = int2ip(bytes_network)
    netmask = long2netmask(bytes_netmask)

    net = u"{0:s}/{1:d}".format(network, netmask)

    if netmask < 16:
        return None

    return net


def get_networks_interfaces() -> dict:
    from scapy.all import conf
    from netaddr import IPNetwork

    networks_interfaces = dict()

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

        if interface != conf.iface:
            # Skipping because scapy currently doesn't support arping on non-primary network interfaces
            continue

        if ip_network is None:
            continue

        networks_interfaces[interface] = ip_network

    return networks_interfaces


def resolve_ip(ip):
    """rdns with a timeout"""
    socket.setdefaulttimeout(2)
    try:
        host = socket.gethostbyaddr(ip)
    except:
        host = None
    if host is not None:
        host = host[0]
    return host
