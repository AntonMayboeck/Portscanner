import csv

import pyfiglet
import sys
import socket
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP, UDP

ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)
ip = "0.0.0.0"
tcp_ports = [80, 443, 53, 22, 1723,
         5060, 8080, 21, 4567, 25,
         3389, 8081, 8000, 110, 10000,
         23, 81, 5000, 8082, 445,
         143, 111, 567, 3306, 110,
         135, 139, 993, 995, 5900]

udp_ports = [161, 123, 53, 500, 111,
             137, 69, 5353]

open_ports = []

def checkhost():
    ping = IP(dst=ip)/ICMP()
    res = sr1(ping,timeout=1,verbose=0)
    if res == None:
        print("This host is down")
    else:
        print("This host is up")


#function to check open port
def checkport():
    # What to do:
    header = ['ip address', 'port', 'date', 'status']
    f = open("scanning.csv", "w")
    writer = csv.writer(f)
    writer.writerow(header)
    for port in tcp_ports:
        timer = datetime.now()
        tcpRequest = IP(dst=ip)/TCP(dport=port, flags="S")
        tcpResponse = sr1(tcpRequest, timeout=1, verbose=0)
        try:
            if tcpResponse.getlayer(TCP).flags == "SA":
                print(port, "is listening")
                data = [ip, port, timer, True]
                writer.writerow(data)
            else:
                data = [ip, port, timer, False]
                writer.writerow(data)
        except AttributeError:
            print(port, "is not listening")
            data = [ip, port, timer, False]
            writer.writerow(data)



checkhost()
checkport()
