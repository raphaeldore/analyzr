from enum import Enum, IntEnum

# List is taken from "Nmap - Scanning the Internet", DEFCON 16
# presentation by Fyodor

           # port   # service name
topports = {80,     # http
            23,     # telnet
            22,     # ssh
            443,    # https
            3389,   # ms-term-serv
            445,    # microsoft-ds
            139,    # netbios-ssn
            21,     # ftp
            135,    # msrpc
            25}     # smtp

NUM_PING_THREADS = 4


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