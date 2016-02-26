import argparse
import signal
import sys
from multiprocessing import freeze_support, Process

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
    freeze_support()
    args = parse_arguments()

    if not args.force and not is_user_admin():
        print("\033[31m [-] Please run as root. \033[0m")
        sys.exit(1)

    analyzr_process = Process(target=_start_analyzr, args=(args,))

    # Capture interrupt signal and cleanup before exiting
    def signal_handler(signal, frame):
        analyzr_process.terminate()
        analyzr_process.join()
        print("Bye bye.")

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    analyzr_process.start()


def _start_analyzr(args):
    from analyzr import main
    main.run(args)


if __name__ == "__main__":
    main()
