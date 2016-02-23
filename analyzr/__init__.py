import logging
import os

from core import config
from fingerprints import EttercapFingerprinter
from networkdiscoverer import NetworkDiscoverer
from networkdiscovery import active, passive

logger = logging.getLogger(__name__)

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


class Analyzr:
    def __init__(self):
        self.config = dict()

    def run(self):
        scanners = list()
        fingerprinters = list()

        # for cls in classes_in_module(fingerprinter):
        #    fingerprinters.append(cls())

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

def classes_in_module(module: object):
    md = module.__dict__
    return [
        md[c] for c in md if (
            isinstance(md[c], type) and md[c].__module__ == module.__name__
        )
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

# Scapy Logging
# Removes "WARNING: Mac address to reach destination not found. Using broadcast" message.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
