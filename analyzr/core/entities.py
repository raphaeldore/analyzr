from netaddr import IPAddress, EUI


class NetworkNode:
    """
    :type ip: IPAddress
    :type mac: EUI
    :type host: str
    """
    def __init__(self, ip = None, mac = None, host = None):
        self.ip = ip
        self.mac = mac
        self.host = host

    def __eq__(self, other):
        return self.ip == other
