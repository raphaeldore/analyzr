import abc
import logging

from netaddr import IPAddress, EUI


class NetworkNode:
    """
    Represents a node in the network.
    """

    def __init__(self, ip: IPAddress = None, mac: EUI = None, host: str = None):
        self.ip = ip
        self.mac = mac
        self.host = host
        self.possible_fingerprints = set()
        self.opened_ports = []

    def __eq__(self, other: IPAddress):
        return self.ip == other

    def __hash__(self):
        return self.ip.__hash__()

    def __str__(self):
        return "{fingerprint} - {ip} - {mac} - {host} - Opened ports: {ports}".format(
            fingerprint=str(self.possible_fingerprints), ip=str(self.ip), mac=str(self.mac),
            host=self.host if self.host else "Unknown host", ports=self.opened_ports)


class AnalyzrModule(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.config = {}
