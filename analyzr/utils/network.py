import math
import socket
import struct


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
