import abc
import logging

from netaddr import IPAddress, EUI

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)

class NetworkNode:
    """
    Represents a node in the network.
    """

    def __init__(self, ip: IPAddress = None, mac: EUI = None, host: str = None):
        self.ip = ip
        self.mac = mac
        self.host = host

    def __eq__(self, other: IPAddress):
        return self.ip == other

    def __hash__(self):
        return self.ip.__hash__()


class AnalyzrModule(object):

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config = {}

