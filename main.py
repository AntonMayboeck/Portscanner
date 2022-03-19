import csv

import random
import pyfiglet
import sys
import socket
from datetime import datetime
from scapy.all import *
import ipaddress
from scapy.layers.inet import ICMP, IP, TCP, UDP

random.seed(344)
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

ip = [x for x in ipaddress.IPv4Network('31.209.224.0/20')]
random.shuffle(ip)
most_common_tcp_ports = [80, 443, 53, 22, 1723,
         5060, 8080, 21, 4567, 25,
         3389, 8081, 8000, 110, 10000,
         23, 81, 5000, 8082, 445,
         143, 111, 567, 3306, 110,
         135, 139, 993, 995, 5900]

most_common_udp_ports = [161, 123, 53, 500, 111,
             137, 69, 5353]

q1 = []
q2 = []
q3 = []

def checkhost():
    for address in ip:
        ping = IP(dst=address)/ICMP()
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
    for address in ip:
        counter = 0
        for port in most_common_tcp_ports:
            timer = datetime.now()
            tcpRequest = IP(dst=address)/TCP(dport=port, flags="S")
            tcpResponse = sr1(tcpRequest, timeout=1, verbose=0)
            try:
                if tcpResponse.getlayer(TCP).flags == "SA":
                    print(port, "is listening")
                    data = [address, port, timer, True]
                    writer.writerow(data)
                    counter += 1
                if tcpResponse.getlayer(TCP).flags == "RA":
                    print(port, "is not listening")
                    data = [address, port, timer, False]
                    writer.writerow(data)
            except AttributeError:
                print(port, "is not listening")
                data = [address, port, timer, False]
                writer.writerow(data)
        if counter >= 5:
            q1.append(address)
        elif 5 > counter > 0:
            q2.append(address)
        else:
            q3.append(address)



checkhost()
checkport()
