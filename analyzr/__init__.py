import socket

from analyzr.core import config

from os import path
graphs_dir = path.join(path.dirname(__file__), "..", 'graphs')

__title__ = 'analyzr'
__version__ = '0.0.1'
__author__ = 'Raphaël Doré & Raphaël Fournier'
__license__ = 'MIT'
__copyright__ = 'Copyright 2016 Raphaël Doré & Raphaël Fournier'

__all__ = [
    'core',
    'graphics',
    'networkdiscovery',
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

# Removes "WARNING: Mac address to reach destination not found. Using broadcast" message.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def main():
    """The main routine."""

    from analyzr import constants
    import argparse

    class PortsAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            min_value = min(values)
            max_value = max(values)

            if min_value < 1:
                parser.error("{0:d} is not a valid port number. Valid range is 1-65535 (inclusive).".format(min_value))
            elif max_value > 65535:
                parser.error("{0:d} is not a valid port number. Valid range is 1-65535 (inclusive).".format(max_value))

            setattr(namespace, self.dest, set(values))

    parser = argparse.ArgumentParser()

    parser.add_argument("-ftcp",
                        "--fastTCP",
                        help="Makes TCPSYNPing only ping on port 80.",
                        action="store_true",
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
                        help="Sets the logging level for the whole application. Possible values are :"
                             " debug, info, warning, error and critical.",
                        choices=["debug", "info", "warning", "error", "critical"],
                        default="debug")

    args = parser.parse_args()

    try:
        from analyzr import runner
        runner.run(args)
    except socket.error as e:
        if e.errno == socket.errno.EPERM:  # Operation not permitted
            print("\033[31m{0:s}\033[0m. Did you run as root?".format(e.strerror))
