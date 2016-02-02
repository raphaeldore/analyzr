from os import getuid

if __name__ == "__main__":
    # perm check
    # TODO: Ça fonctionne tu sur windows?
    if int(getuid()) > 0:
        print("\033[31m [-] Please run as root. \033[0m")
        exit(1)
    from analyzr.main import execute
    execute()