import argparse
import logging
import sys


from analyzr import Analyzr
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

    app = Analyzr()
    app.run()


if __name__ == "__main__":
    main()
