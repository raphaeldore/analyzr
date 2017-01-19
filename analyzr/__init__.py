import os
import socket
from os import path
from sys import platform as _platform
from typing import List

from analyzr.core import InvalidInterface

graphs_dir = path.join(path.dirname(__file__), "..", 'graphs')

__title__ = 'analyzr'
__version__ = '0.0.1'
__author__ = 'Raphaël Doré & Raphaël Fournier'
__license__ = 'MIT'
__copyright__ = 'Copyright 2016 Raphaël Doré & Raphaël Fournier'

__all__ = [
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


def parse_ports(values: List[str]) -> (list, list):
    """
    Function used to parse data received from the user. Valid formats include ranges of ports,
    for example, to scan the ports 1 to 80, you would use 1:80. If one want to scan multiple ports, separate each
    port by a space.

    :param values: Data received by user.
    :return: A tuple (ports, invalid_ports).
    """
    import re
    from analyzr import constants

    valid_port_range = range(constants.MIN_PORT_NUMBER, constants.MAX_PORT_NUMBER + 1)
    range_re = re.compile("\d+:\d+")

    ports = set()
    invalid_ports = []

    for port in values:
        try:
            if range_re.match(port):
                range_start, range_end = (int(i) for i in port.split(":"))
                ports.update(range(range_start, range_end + 1))
            else:
                ports.add(int(port))
        except ValueError:
            invalid_ports.append(port)

    [invalid_ports.append(port) for port in ports if port not in valid_port_range]

    return list(ports), invalid_ports


def parse_networks(values: List[str]) -> (list, list):
    """
    Function used to parse data received by the user concerning the networks he wants to scan.
    The networks must be in CIDR format, for example: 192.168.1.0/24. Also, the network must be
    a private IPV4 address.

    :param values: List of networks in CIDR format (Ex: 192.168.1.0/24).
    :return: list of errors, or an empty list if there are no errors.
    """
    from netaddr import IPNetwork, AddrFormatError

    errors = []
    for net in values:
        try:
            network = IPNetwork(net)
            if "/" not in net:  # we test this here because we are certain that the entered ip address is valid, but missing subnet mask.
                errors.append("{network} is not a valid ip network. The subnet mask is missing. Maybe you meant: {network}/24?"
                              .format(network=net))
            elif not network.is_private():
                errors.append(
                    "{0:s} is not a valid private ip network. This tool only scans the private IPV4 space.".format(net))

        except AddrFormatError:
            errors.append("{0:s} is not a valid ip network.".format(net))

    return errors


def get_program_arguments():
    from analyzr import constants
    import configargparse

    class PortsAction(configargparse.Action):
        import re
        valid_port_range = range(constants.MIN_PORT_NUMBER, constants.MAX_PORT_NUMBER + 1)
        range_re = re.compile("\d+:\d+")

        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(PortsAction, self).__init__(option_strings, dest, nargs, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            # if values come from the config file, then they will be separated by commas
            if len(values) == 1 and "," in values[0]:
                valid_ports, invalid_ports = parse_ports(values[0].split(","))
            else:
                valid_ports, invalid_ports = parse_ports(values)

            if invalid_ports:
                message = "is not a valid port number" if len(invalid_ports) == 1 else "are not valid port numbers"
                parser.error("{ports} {msg}.\nValid range is 1-65535 (inclusive).".format(
                    ports=", ".join([str(ip) for ip in invalid_ports]), msg=message))

            setattr(namespace, self.dest, valid_ports)

    class IPNetworksAction(configargparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(IPNetworksAction, self).__init__(option_strings, dest, nargs, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            # if values come from the config file, then they will be separated by commas
            if len(values) == 1 and "," in values[0]:
                errors = parse_networks(values[0].split(","))
            else:
                errors = parse_networks(values)

            if errors:
                parser.error("\n".join(errors))

            setattr(namespace, self.dest, list(set(values)))

    default_config_files = [os.path.join(os.getcwd(), "analyzr.ini"),
                            os.path.join(os.getcwd(), "config.ini"),
                            os.path.join(os.path.expanduser("~"), ".analyzr.ini")]

    if _platform == "linux":
        user_xdg_config_home = os.getenv("XDG_CONFIG_HOME", None)
        if user_xdg_config_home:
            default_config_files.append(os.path.join(user_xdg_config_home, "analyzr.ini"))

    parser = configargparse.ArgParser(default_config_files=default_config_files,
                                      description="Discover hosts on (or close to) your network!",
                                      epilog="Usage example: -p 22 23 80 443 -ll debug -ettercap_fingerprints "
                                             "C:\\fingerprints\\etter.finger.os")

    parser.add_argument('-c', '--config',
                        is_config_file=True,
                        help='path to config file. See bin/analyzr.sample.ini for example config file.',
                        required=False)
    parser.add_argument("--discovery-mode",
                        help="Decide which host discovery strategy to use.",
                        choices=["passive", "active", "all"])
    parser.add_argument("--ports",
                        help="Ports to scan on hosts (1-65535). Valid inputs include: 80 (single port), 22 23 80 443 "
                             "(multiple ports) and 1:100 (ports 1 to 100). You can also mix and match (Ex: 22:40 80 443)."
                             " Duplicate ports are ignored.",
                        action=PortsAction,
                        nargs='+'
                        )
    parser.add_argument("--log-level",
                        help="Sets the logging level for the whole application.",
                        choices=["debug", "info", "warning", "error", "critical"],
                        default="info")
    parser.add_argument("--ettercap-fingerprints",
                        help="Set the path to the ettercap fingerprints database file.",
                        # type=argparse.FileType('r', encoding='UTF-8'),
                        default=config["ettercap_fingerprints_path"],
                        required=False)
    parser.add_argument("--networks",
                        help="IP networks to scan in CIDR format. If ommited, scans the whole private IPV4 address space.",
                        nargs="+",
                        action=IPNetworksAction,
                        required=False)
    parser.add_argument("--interface",
                        help="The network interface to use to listen to or send packets with",
                        required=False)

    return parser.parse_known_args()


def main():
    """The main routine."""

    args = get_program_arguments()

    logger = logging.getLogger("analyzr")
    logger.setLevel(args[0].log_level.upper())

    try:
        from analyzr import runner
        runner.run(args[0])
    except socket.error as e:
        if e.errno == socket.errno.EPERM:  # Operation not permitted
            print("\033[31m{0:s}\033[0m. Did you run as root?".format(e.strerror))
    except InvalidInterface:
        logger.error("Provided network interface '{interface}' is invalid.".format(interface=args[0].interface))
    except Exception as e:
        logger.exception(e)
