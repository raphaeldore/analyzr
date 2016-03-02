from enum import Enum

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


class DhcpMessageTypes(Enum):
    MESSAGE_TYPE_OFFER = 2
    MESSAGE_TYPE_REQUEST = 3
    MESSAGE_TYPE_ACK = 5
    MESSAGE_TYPE_NAK = 6
    MESSAGE_TYPE_RELEASE = 7