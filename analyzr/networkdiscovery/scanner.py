import abc
from analyzr.core.entities import AnalyzrModule


class Scanner(AnalyzrModule):
    """
    Abstract scanner
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        super(Scanner, self).__init__()
        self.scan_results = dict()

    def scan(self):
        """
        Not implemented in base class.

        :param network: network to scan.
        """
        raise NotImplemented

    @property
    def number_of_hosts_found(self) -> int:
        return sum(len(v) for v in self.scan_results.values())
