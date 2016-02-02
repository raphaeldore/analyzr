from analyzr.networkscanner import NetworkScanner


def execute():
    networkscanner = NetworkScanner()
    networkscanner.scan_and_find_network_nodes_on_networks()
    networkscanner.pretty_print_ips()
    #networkscanner.fingerprints()
    #networkscanner.find_hops()

    #networkscanner.scan_found_network_nodes_for_opened_ports()
    #networkscanner.port_ping_scan()

if __name__ == "__main__":
    execute()
