import collections
import logging

from scapy import packet
from scapy.layers.inet import IP, TCP

from analyzr.core.entities import AnalyzrModule
from analyzr.utils.file import open_with_error
from analyzr.utils.network import TCPFlag


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
        self.logger = logging.getLogger(__name__)

    def load_fingerprints(self):
        raise NotImplemented

    def identify_os_from_pkt(self, pkt: packet):
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

    # EttercapFingerprint = collections.namedtuple("EttercapFingerprint",
    #                                              ['tcp_win_size',
    #                                               'tcp_opt_max_segment_size',
    #                                               "ttl",
    #                                               "tcp_opt_win_scale",
    #                                               'tcp_opt_sack_permitted',
    #                                               'tcp_opt_contains_nop',
    #                                               'ip_dont_fragment_flag_set',
    #                                               'tcp_timestamp_present',
    #                                               'pkt_flag',
    #                                               'pkt_len',
    #                                               'os'])

    def __init__(self, os_fingerprint_file_name: str):
        super().__init__("Ettercap Fingerprinter", os_fingerprint_file_name)
        # A fingerprint can match many operating systems. So the key is the fingerprint.
        self.os_fingerprints = collections.OrderedDict()
        # self.load_fingerprints()

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

                    self.os_fingerprints.setdefault(fingerprint, []).append(vendor)

                    # Is this better?
                    # if len(li) > 29:
                    #    fingerprint = li[:28]
                    #    os_vendor = li[29:]
                    #    self.os_fingerprints.setdefault(fingerprint, []).append(os_vendor)

            # TODO: Remove this. This is only to debug.
            for fingerprint, vendors in self.os_fingerprints.items():
                print("Operating systems matching the fingerprint: ", str(fingerprint), "\n")
                for vendor in vendors:
                    print("\t", vendor, "\n")

            self.logger.debug(
                "Loaded {nb_finger} fingerprints from {file_name}.".format(nb_finger=len(self.os_fingerprints),
                                                                           file_name=self.os_fingerprint_file_name))

    def identify_os_from_pkt(self, pkt: packet) -> list:
        try:
            ettercap_fingerprint = self._pkt_to_ettercap_fingerprint(pkt)
            return self.os_fingerprints[ettercap_fingerprint]
        except KeyError:
            return ["Unknown OS"]
        except (TypeError, ValueError) as e:
            self.logger.warning(str(e))
            return []

    def _pkt_to_ettercap_fingerprint(self, pkt: packet):
        # We don't want to modify the original packet
        pkt = pkt.copy()
        pkt = pkt.__class__(bytes(pkt))

        while pkt.haslayer(IP) and pkt.haslayer(TCP):
            pkt = pkt.getlayer(IP)
            if isinstance(pkt.payload, TCP):
                break
            pkt = pkt.payload

        if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
            raise TypeError("Not a TCP/IP packet")

        if not pkt[TCP].options:
            return self._get_ettercap_fingerprint(
                tcp_window_size=hex(pkt[TCP].window),
                tcp_opt_max_segment_size="",
                ip_ttl=hex(pkt[IP].ttl),
                tcp_opt_window_scale_factor="",
                tcp_opt_sack_permitted=False,
                tcp_opt_no_operation=False,
                ip_flag_dont_fragment="DF" in pkt[IP].flags,
                tcp_opt_timestamp_present=False,
                tcp_flag_syn=pkt[TCP].flags & TCPFlag.SYN == TCPFlag.SYN,
                tcp_flag_ack=pkt[TCP].flags & TCPFlag.ACK == TCPFlag.ACK,
                ip_pkt_total_len=hex(len(pkt[IP]))
            )

        tcp_options = dict(pkt[TCP].options)

        wwww = pkt[TCP].window
        # TCPOptionsField.getfield()
        # mss = pkt[TCP].options[]
        ttl = pkt.ttl
        # ws =

    def _get_ettercap_fingerprint(self,
                                  tcp_window_size: str,  # hex
                                  tcp_opt_max_segment_size: str,  # hex
                                  ip_ttl: str,  # hex
                                  tcp_opt_window_scale_factor: str,  # hex
                                  tcp_opt_sack_permitted: bool,
                                  tcp_opt_no_operation: bool,
                                  ip_flag_dont_fragment: bool,
                                  tcp_opt_timestamp_present: bool,
                                  tcp_flag_syn: bool,
                                  tcp_flag_ack: bool,
                                  ip_pkt_total_len: str):  # hex
        fingerprint_builder = []
        fingerprint_builder.append(tcp_window_size)
        fingerprint_builder.append(tcp_opt_max_segment_size if tcp_opt_max_segment_size else "_MSS")
        fingerprint_builder.append(ip_ttl)
        fingerprint_builder.append(tcp_opt_window_scale_factor if tcp_opt_window_scale_factor else "WS")
        fingerprint_builder.append("1" if tcp_opt_sack_permitted else "0")
        fingerprint_builder.append("1" if tcp_opt_no_operation else "0")
        fingerprint_builder.append("1" if ip_flag_dont_fragment else "0")
        fingerprint_builder.append("1" if tcp_opt_timestamp_present else "0")

        if tcp_flag_syn and not tcp_flag_ack:
            fingerprint_builder.append("S")
        elif tcp_flag_syn and tcp_flag_ack:
            fingerprint_builder.append("A")
        else:
            raise ValueError("Not a SYN or SYN/ACK packet")

        fingerprint_builder.append(ip_pkt_total_len if ip_pkt_total_len else "LT")

        return self.EttercapFingerprint(*fingerprint_builder)



        # def _get_ettercap_fingerprint(self, **kwargs):
        #    pass
