import math
import socket
import struct
from enum import Enum
from scapy.all import conf
from netaddr import IPNetwork, IPAddress


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


class ICMPType(Enum):
    ECHO_REPLY              = 0
    DEST_UNREACHABLE        = 3
    SOURCE_QUENCH           = 4
    REDIRECT                = 5
    ECHO_REQUEST            = 8
    ROUTER_ADVERTISEMENT    = 9
    ROUTER_SOLICITATION     = 10
    TIME_EXCEEDED           = 11
    PARAMETER_PROBLEM       = 12
    TIMESTAMP_REQUEST       = 13
    TIMESTAMP_REPLY         = 14
    INFORMATION_REQUEST     = 15
    INFORMATION_RESPONSE    = 16
    ADDRESS_MASK_REQUEST    = 17
    ADDRESS_MASK_REPLY      = 18

class ICMPCode(Enum):
    # DEST_UNREACHABLE (3)
    NETWORK_UNREACHABLE         = 0
    HOST_UNREACHABLE            = 1
    PROTOCOL_UNREACHABLE        = 2
    PORT_UNREACHABLE            = 3
    FRAGMENTATION_NEEDED        = 4
    SOURCE_ROUTE_FAILED         = 5
    NETWORK_UNKNOWN             = 6
    HOST_UNKNOWN                = 7
    NETWORK_PROHIBITED          = 9
    HOST_PROHIBITED            = 10
    TOS_NETWORK_UNREACHABLE    = 11
    TOS_HOST_UNREACHABLE       = 12
    COMMUNICATION_PROHIBITED   = 13
    HOST_PRECEDENCE_VIOLATION  = 14
    PRECEDENCE_CUTOFF          = 15

    # REDIRECT (5)
    NETWORK_REDIRECT        = 0
    HOST_REDIRECT           = 1
    TOS_NETWORK_REDIRECT    = 2
    TOS_HOST_REDIRECT       = 3

    # TIME_EXCEEDED (11)
    TTL_ZERO_DURING_TRANSIT     = 0
    TTL_ZERO_DURING_REASSEMBLY  = 1

    # PARAMETER_PROBLEM (12)
    IP_HEADER_BAD           = 0
    REQUIRED_OPTION_MISSING = 1

class ScapyTCPFlag:
    SYN = "S"
    ACK = "A"
    RST = "R"

class TCPFlag(Enum):
    NULL    = 0x00
    FIN     = 0x01
    SYN     = 0x02
    RST     = 0x04
    PSH     = 0x08
    ACK     = 0x10
    URG     = 0x20

    def __or__(self, other):
        return self.value | other.value


    # Si on veut un SYN-ACK on fait: SYN_ACK = SYN | ACK
