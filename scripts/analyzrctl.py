import os
import signal
import sys
from multiprocessing import Process

import analyzr

lib_path = os.path.abspath(os.path.join('..', 'analyzr'))
sys.path.append(lib_path)

import argparse
import logging

from analyzr.core import config
from analyzr.utils.admin import isUserAdmin


def main():
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

    logger = logging.getLogger("analyzr")

    logger.setLevel(logging.DEBUG if config.debug else logging.INFO)

    args = parser.parse_args()
    if not args.force:
        try:
            # perm check
            if not isUserAdmin():
                logger.error("\033[31m [-] Please run as root. \033[0m")
                sys.exit(1)
        except RuntimeError as re:
            logger.error(str(re))
            sys.exit(1)

    config.fastTCP = args.fastTCP

    analyzr_process = Process(target=analyzr.execute, args=())
    analyzr_process.start()

    # Capture interrupt signal and cleanup before exiting
    def signal_handler(signal, frame):
        analyzr_process.terminate()
        analyzr_process.join()

        logger.info("Bye bye :)")

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    main()
