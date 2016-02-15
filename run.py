import argparse
import logging
import sys

from analyzr.core import config
from analyzr.utils.admin import isUserAdmin
from core.config import init_config


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--force",
                        help="Force run the application. Even if not root. Warning : things most probably won't work.",
                        action='store_true', default=False)
    parser.add_argument("-ftcp", "--fastTCP", help="Makes TCPSYNPing only ping on port 80.", action="store_true",
                        default=False)
    return parser.parse_args()


def main():
    logger = logging.getLogger("analyzr")

    init_config()
    logger.setLevel(logging.DEBUG if config.debug else logging.INFO)

    args = parse_args()
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

    from analyzr.main import execute

    execute()


if __name__ == "__main__":
    main()
