from analyzr.networkscanner import NetworkScanner


def execute():
    networkscanner = NetworkScanner()
    networkscanner.port_ping_scan()

if __name__ == "__main__":
    execute()
