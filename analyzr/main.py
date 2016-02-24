import argparse
import logging
import os
import signal
import sys
from multiprocessing import Process

lib_path = os.path.abspath(os.path.join('..', 'analyzr'))
sys.path.append(lib_path)


from analyzr.fingerprints import EttercapFingerprinter
from analyzr.networkdiscovery import active, passive
from analyzr.networkdiscoverer import NetworkDiscoverer
from analyzr.utils.admin import is_user_admin

logger = logging.getLogger(__name__)

LOG_LEVELS = { 'debug':logging.DEBUG,
            'info':logging.INFO,
            'warning':logging.WARNING,
            'error':logging.ERROR,
            'critical':logging.CRITICAL,
            }

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-f",
                        "--force",
                        help="Force run the application. Even if not root. Warning : things most probably won't work.",
                        action='store_true',
                        default=False)
    parser.add_argument("-ftcp",
                        "--fastTCP", help="Makes TCPSYNPing only ping on port 80.",
                        action="store_true",
                        default=False)
    parser.add_argument("-ll",
                        "--log-level",
                        help="Sets the logging level for the whole application. Possible values are : debug, info, warning, error and critical.",
                        default="debug",
                        choices= LOG_LEVELS.keys())

    return parser.parse_args()


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


def run():
    args = parse_arguments()
    logger = logging.getLogger("analyzr")
    logger.setLevel(LOG_LEVELS.get(args.log_level))

    if not args.force:
        try:
            # perm check
            if not is_user_admin():
                logger.error("\033[31m [-] Please run as root. \033[0m")
                sys.exit(1)
        except RuntimeError as re:
            logger.error(str(re))
            sys.exit(1)

    analyzr_process = Process(target=_scan, args=(args,))

    analyzr_process.start()

    # Capture interrupt signal and cleanup before exiting
    def signal_handler(signal, frame):
        analyzr_process.terminate()
        analyzr_process.join()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)


def _scan(args):
    read_config()

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
    from analyzr import config
    if config.activescan:
        for cls in classes_in_module(active):
            scanners.append(cls())
    if config.passivescan:
        for cls in classes_in_module(passive):
            scanners.append(cls())

    networkscanner = NetworkDiscoverer(scanners, fingerprinters)

    networkscanner.discover()


if __name__ == "__main__":
    run()
