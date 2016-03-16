import logging

import collections

from analyzr.core import AnalyzrModule
from analyzr.utils.file import open_with_error


# TODO: Is passing a packet conversion function very clean..? Seems a bit hackish. My design is not the best.
# FIXME: This is a temporary solution. Probably best to just implement independent functions in NetworkTool..
#        because depending on the fingerprinter, we must craft packets in specific ways.

class Fingerprinter(AnalyzrModule):
    def __init__(self, name: str, os_fingerprint_file_name: str, pkt_conversion_fn: callable):
        super().__init__(name)
        self.os_fingerprint_file_name = os_fingerprint_file_name
        self.pkt_conversion_fn = pkt_conversion_fn
        self.logger = logging.getLogger(__name__)

    def load_fingerprints(self):
        raise NotImplemented

    def identify_os_from_pkt(self, pkt) -> set:
        raise NotImplemented


class EttercapFingerprinter(Fingerprinter):
    """
    The fingerprint database has the following structure:

    WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS

    WWWW: 4 digit hex field indicating the TCP Window Size
    MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size
          if omitted in the packet or unknown it is "_MSS"
    TTL : 2 digit hex field indicating the IP Time To Live
    WS  : 2 digit hex field indicating the TCP Option Window Scale
          if omitted in the packet or unknown it is "WS"
    S   : 1 digit field indicating if the TCP Option SACK permitted is true
    N   : 1 digit field indicating if the TCP Options contain a NOP
    D   : 1 digit field indicating if the IP Don't Fragment flag is set
    T   : 1 digit field indicating if the TCP Timestamp is present
    F   : 1 digit ascii field indicating the flag of the packet
          S = SYN
          A = SYN + ACK
    LEN : 2 digit hex field indicating the length of the packet
          if irrilevant or unknown it is "LT"
    OS  : an ascii string representing the OS
    """

    # Does not contain OS, because a fingerprint can be linked to multiple operating systems.
    EttercapFingerprint = collections.namedtuple("EttercapFingerprint",
                                                 ['WWWW',
                                                  'MSS',
                                                  "TTL",
                                                  "WS",
                                                  'S',
                                                  'N',
                                                  'D',
                                                  'T',
                                                  'F',
                                                  'LEN'])

    def __init__(self, os_fingerprint_file_name: str, pkt_conversion_fn: callable):
        super().__init__("Ettercap Fingerprinter", os_fingerprint_file_name, pkt_conversion_fn)
        # A fingerprint can match many operating systems. So the key is the fingerprint.
        self.os_fingerprints = collections.OrderedDict()

    def load_fingerprints(self):
        with open_with_error(filename=self.os_fingerprint_file_name, mode="r", encoding="utf-8") as (
                fingerprint_db, err):
            if err:
                raise err

            for line in fingerprint_db:
                li = line.strip()  # type: str
                if li and not li.startswith("#"):
                    # WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS
                    split_line = li.split(":", maxsplit=10)
                    vendor = split_line[10]
                    fingerprint = self.EttercapFingerprint(*split_line[:-1])  # on ignore l'os

                    self.os_fingerprints.setdefault(fingerprint, set()).add(vendor)

            self.logger.debug(
                "Loaded {nb_finger} fingerprints from {file_name}.".format(nb_finger=len(self.os_fingerprints),
                                                                           file_name=self.os_fingerprint_file_name))

    def identify_os_from_pkt(self, pkt) -> set:
        try:
            converted_pkt = self.pkt_conversion_fn(pkt)
            ettercap_fingerprint, ettercap_fingerprint_wo_len = self._get_ettercap_fingerprint(*converted_pkt)

            found_fingerprint = self.os_fingerprints.get(ettercap_fingerprint, None)

            # Take 2, this time without length
            if not found_fingerprint and ettercap_fingerprint_wo_len:
                found_fingerprint = self.os_fingerprints.get(ettercap_fingerprint_wo_len, None)

            return found_fingerprint if found_fingerprint else {}
        except (TypeError, ValueError):
            return {}

    def _get_ettercap_fingerprint(self,
                                  tcp_window_size,  # 4 digit hex
                                  tcp_opt_max_segment_size,  # 4 digit hex
                                  ip_ttl,  # 2 digit hex
                                  tcp_opt_window_scale_factor,  # 2 digit hex
                                  tcp_opt_sack_permitted,
                                  tcp_opt_no_operation,
                                  ip_flag_dont_fragment,
                                  tcp_opt_timestamp_present,
                                  tcp_flag_syn,
                                  tcp_flag_ack,
                                  ip_pkt_total_len) -> (EttercapFingerprint, EttercapFingerprint):  # 2 digit hex

        fingerprint = []
        fingerprint.append(format(tcp_window_size, "04X"))
        fingerprint.append(format(tcp_opt_max_segment_size, "04X") if tcp_opt_max_segment_size else "_MSS")
        fingerprint.append(format(ip_ttl, "02X"))
        fingerprint.append(format(tcp_opt_window_scale_factor, "02X") if tcp_opt_window_scale_factor else "WS")
        fingerprint.append("1" if tcp_opt_sack_permitted else "0")
        fingerprint.append("1" if tcp_opt_no_operation else "0")
        fingerprint.append("1" if ip_flag_dont_fragment else "0")
        fingerprint.append("1" if tcp_opt_timestamp_present else "0")

        if tcp_flag_syn and not tcp_flag_ack:
            fingerprint.append("S")
        elif tcp_flag_syn and tcp_flag_ack:
            fingerprint.append("A")
        else:
            raise ValueError("Not a SYN or SYN/ACK packet")

        # Per etter.finger.os, the packet length can sometimes be irrelevant.
        # So to maximize chances, we return 2 fingerprints : One with the total
        # length set to "LT", and the other one with the packet length.
        # If ip_pkt_total_len is empty or null, then this does not apply.
        fingerprint_wo_len = []
        if ip_pkt_total_len:
            fingerprint_wo_len = list(fingerprint)
            fingerprint.append(format(ip_pkt_total_len, "02X"))
            fingerprint_wo_len.append("LT")
        else:
            fingerprint.append("LT")

        return (self.EttercapFingerprint(*fingerprint),
                self.EttercapFingerprint(*fingerprint_wo_len) if fingerprint_wo_len else None)


# For testing only...
# if __name__ == "__main__":
#     from scapy.all import *
#     from scapy.layers.inet import IP, TCP
#     from analyzr.networktool import ScapyTool
#     from analyzr.constants import topports
#
#     ettercap_fingerprinter = EttercapFingerprinter(
#         os_fingerprint_file_name=os.path.join(os.path.dirname(__file__), "resources", "etter.finger.os"),
#         pkt_conversion_fn=ScapyTool.pkt_to_ettercap_fn())
#
#     ettercap_fingerprinter.load_fingerprints()
#     srcPort = random.randint(1025, 65534)
#     ans, unans = sr(IP(dst="172.16.2.1") / TCP(sport=srcPort, dport=list(topports), flags="S"), timeout=1)
#
#     results = []
#     for s, r in ans.res:
#         result = ettercap_fingerprinter.identify_os_from_pkt(r)
#         if result:
#             results.append(result)
#
#     # On my host machine prints: [{'Linux'}, {'Linux'}, {'Linux'}]
#     print(results)
