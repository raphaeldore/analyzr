from scapy import packet

from analyzr.core.entities import AnalyzrModule


class NodeFingerprint:
    def __init__(self, os: str = None, category: str = None, family: str = None, opened_tcp_ports: list = None):
        self.os = os
        self.category = category
        self.opened_tcp_ports = opened_tcp_ports
        self.family = family


class Fingerprinter(AnalyzrModule):
    def __init__(self, name: str, os_fingerprint_file_name: str):
        super().__init__(name)
        self.os_fingerprint_file_name = os_fingerprint_file_name
        self.os_fingerprints = dict()

    def load_fingerprints(self):
        raise NotImplemented

    def identify_os_from_pkt(self, pkt: packet):
        raise NotImplemented


class EttercapFingerprinter(Fingerprinter):
    def __init__(self, os_fingerprint_file_name: str):
        super().__init__("Ettercap Fingerprinter", os_fingerprint_file_name)

    def load_fingerprints(self):
        with(self.os_fingerprint_file_name, "r") as fingerprint_db:
            pass


    def identify_os_from_pkt(self, pkt: packet):
        pass
