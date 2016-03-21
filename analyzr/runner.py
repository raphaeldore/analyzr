import logging

logger = logging.getLogger(__name__)

# FIXME: Not convinced that this class should exist. But not sure what to replace it with...


def run(args):
    from analyzr.fingerprinters import EttercapFingerprinter
    from analyzr.networkdiscoverer import NetworkDiscoverer
    from analyzr.networktool import ScapyTool

    fingerprinters = list()
    fingerprinters.append(EttercapFingerprinter(args.ettercap_fingerprints, ScapyTool.pkt_to_ettercap_fn()))

    for fingerprinter in fingerprinters:
        try:
            fingerprinter.load_fingerprints()
        except FileNotFoundError:
            logger.error(
                "{fingerprinter} : Unable to load {fingerprints}".format(fingerprinter=fingerprinter.name,
                                                                         fingerprints=fingerprinter.os_fingerprint_file_name))

    conf = {"networks": args.networks, "ports": args.ports, "discovery_mode": args.discovery_mode}
    scapytool = ScapyTool(interface_to_use=args.interface, fingerprinters=fingerprinters)
    networkscanner = NetworkDiscoverer(network_tool=scapytool, config=conf)

    if networkscanner.discover():
        networkscanner.scan_found_network_nodes_for_opened_ports()
        networkscanner.find_hops()
        networkscanner.make_network_graph()
        networkscanner.identify_fingerprints()
        networkscanner.pretty_print_ips()
    else:
        print("Discovery found no hosts for specified networks ({nets}) :(.".format(nets=", ".join(args.networks)))
