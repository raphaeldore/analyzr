import abc
import logging

import netaddr


class NetworkNode(object):
    """
    Represents a node in the network.
    """

    # ip - mac - host - hops - opened_ports - closed_ports - possibles fingerprints
    str_template = "{0:15s}|{1:17s}|{2:3s}|{3:30s}|{4:15s}|{5:15s}|6:30s}"

    def __init__(self, ip: netaddr.IPAddress = None, mac: netaddr.EUI = None, host: str = None):
        self.ip = ip
        self.mac = mac
        self.host = host
        self.possible_fingerprints = set()
        self.opened_ports = []
        self.closed_ports = []
        self.hops = []

    def __eq__(self, other: netaddr.IPAddress):
        return self.ip == other

    def __hash__(self):
        return self.ip.__hash__()

    def __str__(self):
        return self.str_template.format(
            str(self.ip),
            str(self.mac),
            self.host or "Unknown host",
            "{nb_hops} hops : {hops}".format(nb_hops=len(self.hops), hops=" --> ".join(hop for hop in self.hops)),
            str(self.opened_ports).strip("[]"),
            str(self.closed_ports).strip("[]"),
            ", ".join(str(e) for e in self.possible_fingerprints))


class AnalyzrModule(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(__name__)
        self.config = {}
