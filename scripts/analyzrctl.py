import os
import sys

lib_path = os.path.abspath(os.path.join('..', 'analyzr'))
sys.path.append(lib_path)

import analyzr.main




def main():
    analyzr.main.run()


if __name__ == "__main__":
    main()
