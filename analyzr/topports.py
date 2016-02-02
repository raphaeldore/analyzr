# Taken from https://github.com/j0k3r-92/TCP-SYN-scanner/blob/1b8e3d6491f205a840cedbeb9eb1a543034497f2/topports.py

# List top ten TCP ports

# List is taken from "Nmap - Scanning the Internet", DEFCON 16
# presentation by Fyodor

           # port   # service name
topports = [80,     # http
            23,     # telnet
            22,     # ssh
            443,    # https
            3389,   # ms-term-serv
            445,    # microsoft-ds
            139,    # netbios-ssn
            21,     # ftp
            135,    # msrpc
            25]     # smtp