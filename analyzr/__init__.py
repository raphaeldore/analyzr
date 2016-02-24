import logging

from analyzr.core import config

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
