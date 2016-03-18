import os
import socket
from os import path

from analyzr.networktool import InvalidInterface

graphs_dir = path.join(path.dirname(__file__), "..", 'graphs')

__title__ = 'analyzr'
__version__ = '0.0.1'
__author__ = 'Raphaël Doré & Raphaël Fournier'
__license__ = 'MIT'
__copyright__ = 'Copyright 2016 Raphaël Doré & Raphaël Fournier'

__all__ = [
    'core',
    'graphics',
    'topology',
    'utils'
]

# Set default logging handler to avoid "No handler found" warnings.
import logging

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

from logging.config import dictConfig

logging_config = dict(
    version=1,
    formatters={
        'verbose': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        }
    },
    handlers={
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'level': logging.DEBUG
        }
    },
    loggers={
        "analyzr": {
            'handlers': ['console'],
            'level': logging.DEBUG
        }
    }
)

logging.config.dictConfig(logging_config)

logging.getLogger(__name__).addHandler(NullHandler())

from analyzr.config import config

dir = os.path.dirname(__file__)
config["ettercap_fingerprints_path"] = os.path.join(dir, "resources", "etter.finger.os")
config["nmap_fingerprints_path"] = os.path.join(dir, "resources", "nmap-os-db")
config["p0f_fingerprints_path"] = os.path.join(dir, "resources", "p0f.fp")


def main():
    """The main routine."""

    from analyzr import constants
    import argparse

    # noinspection PyClassHasNoInit
    class PortsAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            invalid_values = [value for value in values if
                              value < constants.MIN_PORT_NUMBER or value > constants.MAX_PORT_NUMBER]

            if invalid_values:
                invalid_values.sort(key=int)
                message = "is not a valid port number." if len(invalid_values) == 1 else "are not valid port numbers"
                parser.error("{ports} {msg}.\nValid range is 1-65535 (inclusive).".format(
                    ports=", ".join([str(iv) for iv in invalid_values]), msg=message))

            setattr(namespace, self.dest, list(set(values)))

    class IPNetworksAction(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(IPNetworksAction, self).__init__(option_strings, dest, nargs, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            from netaddr import IPNetwork, AddrFormatError

            errors = []

            for net in values:
                if "/" not in net:
                    errors.append("{0:s} is not valid ip network. Missing subnet mask.".format(net))

                try:
                    network = IPNetwork(net)
                    if not network.is_private():
                        errors.append("{0:s} is not valid private ip network. This tool only scans the private IPV4 space.".format(net))
                except AddrFormatError:
                    errors.append("{0:s} is not valid ip network.".format(net))

            if errors:
                parser.error("\n".join(errors))

            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(description="Discover hosts on (or close to) your network!",
                                     epilog="Usage example: -p 22 23 80 443 -ll debug -ett "
                                            "C:\\fingerprints\\etter.finger.os")

    # action="store_true"

    parser.add_argument("-dm",
                        "--discovery-mode",
                        help="Decide which host discovery strategy to use.",
                        choices=["passive", "active", "all"],
                        default=False)
    parser.add_argument("-p",
                        "--ports",
                        nargs="*",
                        help="Ports to scan on hosts (1-65534).",
                        action=PortsAction,
                        type=int,
                        default=constants.topports
                        )
    parser.add_argument("-ll",
                        "--log-level",
                        help="Sets the logging level for the whole application.",
                        choices=["debug", "info", "warning", "error", "critical"],
                        default="info")
    parser.add_argument("-ett",
                        "--ettercap-fingerprints",
                        help="Set the path to the ettercap fingerprint database file.",
                        # type=argparse.FileType('r', encoding='UTF-8'),
                        default=config["ettercap_fingerprints_path"],
                        required=False)
    parser.add_argument("-n",
                        "--networks",
                        help="IP networks to scan in CIDR format. If ommited, scans the whole private IPV4 address space.",
                        nargs="*",
                        action=IPNetworksAction,
                        required=False)

    args = parser.parse_args()

    try:
        from analyzr import runner
        runner.run(args)
    except socket.error as e:
        if e.errno == socket.errno.EPERM:  # Operation not permitted
            print("\033[31m{0:s}\033[0m. Did you run as root?".format(e.strerror))
    except InvalidInterface:
        print("Provided network interface is invalid.")
