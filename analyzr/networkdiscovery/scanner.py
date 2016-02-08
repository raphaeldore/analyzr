import abc

from analyzr.core.config import conf
from analyzr.core.entities import AnalyzrModule


class Scanner(AnalyzrModule):
    """
    Abstract scanner
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        super(Scanner, self).__init__()
        self.scan_results = dict()
        self.config.update({"networks_interfaces": conf.networks_interfaces.items()})
        self.config.update({"timeout": conf.timeout})

    def scan(self):
        """
        Not implemented in base class.

        :param network: network to scan.
        """
        raise NotImplemented
