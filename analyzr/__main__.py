import argparse
import sys

from analyzr.utils.admin import is_user_admin


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
                        choices=["debug", "info", "warning", "error", "critical"])

    return parser.parse_args()


def main():
    """The main routine."""
    args = parse_arguments()

    if not args.force and not is_user_admin():
        print("\033[31m [-] Please run as root. \033[0m")
        sys.exit(1)

    from analyzr import analyzr
    analyzr.run(args)


if __name__ == "__main__":
    main()
