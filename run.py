import sys

from analyzr.utils.admin import isUserAdmin

if __name__ == "__main__":

    if not __debug__:
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
