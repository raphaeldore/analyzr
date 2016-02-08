import sys
import argparse

from analyzr.utils.admin import isUserAdmin


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--force",
                        help="Force run the application. Even if not root. Warning : things most probably won't work.",
                        action='store_true', default=False)
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()
    if not args.force:
        try:
            # perm check
            if not isUserAdmin():
                print("\033[31m [-] Please run as root. \033[0m")
                sys.exit(1)
        except RuntimeError as re:
            print(str(re))
            sys.exit(1)

    from analyzr.main import execute

    execute()
