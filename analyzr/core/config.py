from analyzr.utils.network import get_networks_interfaces


class Configuration:
    networks_interfaces = get_networks_interfaces()
    debug = True
    passivescan = True
    # TODO : Non fonctionnel pour l'instant. Changer à True lorsque fonctionnel
    activescan = True
    timeout = 10
    arping_timeout = 1
    fastTCP = False

conf = Configuration()
