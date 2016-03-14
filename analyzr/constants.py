from enum import IntEnum

# List is taken from "Nmap - Scanning the Internet", DEFCON 16
# presentation by Fyodor

# port   # service name
topports = {80,  # http
            23,  # telnet
            22,  # ssh
            443,  # https
            3389,  # ms-term-serv
            445,  # microsoft-ds
            139,  # netbios-ssn
            21,  # ftp
            135,  # msrpc
            25}  # smtp

NUM_PING_THREADS = 4

MIN_PORT_NUMBER = 1
MAX_PORT_NUMBER = 65535


class DhcpMessageTypes(IntEnum):
    MESSAGE_TYPE_OFFER = 2
    MESSAGE_TYPE_REQUEST = 3
    MESSAGE_TYPE_ACK = 5
    MESSAGE_TYPE_NAK = 6
    MESSAGE_TYPE_RELEASE = 7


class TCPFlag(IntEnum):
    NULL = 0x00
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    def is_flag(tcp_flag, integer):
        return tcp_flag & integer == tcp_flag

        # Si on veut un SYN-ACK on fait tout simplement:
        #   SYN_ACK = TCPFlag.SYN | TCPFlag.ACK


class ICMPType(IntEnum):
    ECHO_REPLY = 0
    DEST_UNREACHABLE = 3
    SOURCE_QUENCH = 4
    REDIRECT = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12
    TIMESTAMP_REQUEST = 13
    TIMESTAMP_REPLY = 14
    INFORMATION_REQUEST = 15
    INFORMATION_RESPONSE = 16
    ADDRESS_MASK_REQUEST = 17
    ADDRESS_MASK_REPLY = 18


class ICMPCode(IntEnum):
    # DEST_UNREACHABLE (3)
    NETWORK_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    NETWORK_UNKNOWN = 6
    HOST_UNKNOWN = 7
    NETWORK_PROHIBITED = 9
    HOST_PROHIBITED = 10
    TOS_NETWORK_UNREACHABLE = 11
    TOS_HOST_UNREACHABLE = 12
    COMMUNICATION_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF = 15

    # REDIRECT (5)
    NETWORK_REDIRECT = 0
    HOST_REDIRECT = 1
    TOS_NETWORK_REDIRECT = 2
    TOS_HOST_REDIRECT = 3

    # TIME_EXCEEDED (11)
    TTL_ZERO_DURING_TRANSIT = 0
    TTL_ZERO_DURING_REASSEMBLY = 1

    # PARAMETER_PROBLEM (12)
    IP_HEADER_BAD = 0
    REQUIRED_OPTION_MISSING = 1


class IPFlag(IntEnum):
    EVIL = 0b00000000  # (0) Reserved Bit A.K.A the "Evil Bit "
    DF = 0b00000010  # (1) Don't fragment
    MF = 0b00000100  # (2) More fragments
