import threading

from scapy.all import *
from scapy.layers.inet import IP, TCP


class PortScanThread(threading.Thread):
    def __init__(self, portlist, tid, target, results):
        threading.Thread.__init__(self)
        self.portlist = portlist
        self.tid = tid
        self.target = target
        self.results = results


    def run(self):
        print("started Thread #{0:d}. Target is: {1:s}.".format(self.tid, self.target.ip))

        openedports = []
        for port in self.portlist:
            response = sr1(IP(dst=self.target.ip)/TCP(dport=port, flags="S"),verbose=False, timeout=0.2)

            if response:
                # flags is 18 if SYN,ACK received
                # i.e port is open
                if TCP in response and response[TCP].flags == 18:
                    openedports.append(port)

        self.results[self.tid] = {self.target : openedports}