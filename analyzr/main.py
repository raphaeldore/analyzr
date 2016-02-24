import importlib
import logging
import os

LOG_LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL,
              }


def classes_in_module(module: object):
    md = module.__dict__
    return [
        md[c] for c in md if (
            isinstance(md[c], type) and md[c].__module__ == module.__name__
        )
        ]


def run(args):
    # init scapy
    importlib.import_module("scapy.all")

    from analyzr import config
    from analyzr.fingerprints import EttercapFingerprinter
    from analyzr.networkdiscoverer import NetworkDiscoverer
    from analyzr.networkdiscovery import active, passive
    from analyzr.utils.network import get_local_interfaces_networks
    from scapy.all import conf

    # Make scapy shut up
    # Removes "WARNING: Mac address to reach destination not found. Using broadcast" message.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    conf.verb = 0

    logger = logging.getLogger("analyzr")
    logger.setLevel(LOG_LEVELS.get(args.log_level))

    config.interfaces_networks, config.networks_ips = get_local_interfaces_networks()

    scanners = list()
    fingerprinters = list()

    dir = os.path.dirname(__file__)

    fingerprinters.append(EttercapFingerprinter(os.path.join(dir, "resources", "etter.finger.os")))

    for fingerprinter in fingerprinters:
        try:
            fingerprinter.load_fingerprints()
        except FileNotFoundError:
            logger.error(
                "{fingerprinter} : Unable to load {fingerprints}".format(fingerprinter=fingerprinter.name,
                                                                         fingerprints=fingerprinter.os_fingerprint_file_name))

    if config.activescan:
        for cls in classes_in_module(active):
            scanners.append(cls())
    if config.passivescan:
        for cls in classes_in_module(passive):
            scanners.append(cls())

    networkscanner = NetworkDiscoverer(scanners, fingerprinters)

    networkscanner.discover()
