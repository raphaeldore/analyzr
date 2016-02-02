from analyzr.networkscanner import NetworkScanner


def execute():
    networkscanner = NetworkScanner()
    networkscanner.scan_and_find_live_hosts_on_networks()
    networkscanner.pretty_print_ips()
    #networkscanner.port_ping_scan()

if __name__ == "__main__":
    execute()
