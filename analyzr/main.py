from analyzr.core.config import conf
from analyzr.networkdiscoverer import NetworkDiscoverer
from analyzr.networkdiscovery import active
from analyzr.networkdiscovery import passive


def read_config():
    # config_file = yaml.load()
    pass


def classes_in_module(module: object):
    md = module.__dict__
    return [
        md[c] for c in md if (
            isinstance(md[c], type) and md[c].__module__ == module.__name__
        )
        ]


def execute():
    read_config()

    scanners = list()

    if conf.activescan:
        for cls in classes_in_module(active):
            scanners.append(cls())
    if conf.passivescan:
        for cls in classes_in_module(passive):
            scanners.append(cls())

    networkscanner = NetworkDiscoverer(scanners)

    networkscanner.discover()
    networkscanner.pretty_print_ips()

    #networkscanner.scan_and_find_network_nodes_on_networks()
    #networkscanner.pretty_print_ips()
    # networkscanner.fingerprints()
    # networkscanner.find_hops()

    # networkscanner.scan_found_network_nodes_for_opened_ports()
    # networkscanner.port_ping_scan()


if __name__ == "__main__":
    execute()
