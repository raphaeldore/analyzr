from analyzr.utils.network import get_local_interfaces_networks

interfaces_networks, networks_ips = get_local_interfaces_networks()
passivescan = True
activescan = True
fastTCP = True
scan_local_network_as_public = False
debug = True
snifferdiscovery_timeout = 10 # Scan for x secondes
num_ping_threads = 16


# class AnalyzrConfig():
#     def __init__(self):
#         network_ips, networks_interfaces = get_local_interfaces_networks()
#
#         self.opts = {'iface': networks_interfaces,
#                      'debug': False,
#                      "ip_addrs": network_ips}
#
#     def __getattr__(self, name):
#         if name in self:
#             return name
#         raise AttributeError
