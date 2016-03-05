import abc
import logging

from netaddr import IPAddress, EUI


class NetworkNode(object):
    """
    Represents a node in the network.
    """

    # ip - mac - host - opened_ports - closed_ports - possibles fingerprints
    str_template = "{0:15s}|{1:17s}|{2:30s}|{3:15s}|{4:15s}|5:30s}"

    def __init__(self, ip: IPAddress = None, mac: EUI = None, host: str = None):
        self.ip = ip
        self.mac = mac
        self.host = host
        self.possible_fingerprints = set()
        self.opened_ports = []
        self.closed_ports = []

    def __eq__(self, other: IPAddress):
        return self.ip == other

    def __hash__(self):
        return self.ip.__hash__()

    def __str__(self):
        return self.str_template.format(
            str(self.ip),
            str(self.mac),
            self.host or "Unknown host",
            str(self.opened_ports).strip("[]"),
            str(self.closed_ports).strip("[]"),
            ", ".join(str(e) for e in self.possible_fingerprints))


class AnalyzrModule(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.config = {}
