import ipaddress
import time
import datetime
import random
import nmap
import csv
# from scapy.layers.inet import IP, ICMP

# example of open port f"nmap -p 22 129.241.150.250"

queue1 = [] # IP addresses with more than 5 of the most common ports open
queue2 = [] # IP adressess with between 1 and 5 of the most common ports open
queue3 = [] # IP addresses with no of the most common ports open
queue4 = [] # IP addresses that are down

common_ports = [
    80, 443, 53, 22, 1723,
    5060, 8080, 21, 4567, 25,
    3389, 8081, 8000, 110, 10000,
    23, 81, 5000, 8082, 445,
    143, 111, 567, 3306, 110,
    135, 139, 993, 995, 5900
]

other_ports = [port for port in range(1, 65536) if port not in common_ports]

def get_ip_range_suffled(cidr: str) -> list[str]:
    ip_list = []
    for ip in ipaddress.IPv4Network(cidr):
        ip_list.append(str(ip))
    random.shuffle(ip_list)
    return ip_list

def scan_most_common(ips: list[str], writer: csv.writer) -> None:
    nm = nmap.PortScanner()
    for ip in ips:
        open_ports = 0
        for port in common_ports:
            res = nm.scan(ip, str(port))
            if res["scan"]:
                if res["scan"][ip]["tcp"][port]["state"] == "open":
                    open_ports += 1
                    data = [ip, port, datetime.datetime.now(), "Y"]
                    writer.writerow(data)
            else:
                open_ports = -1
                break
            time.sleep(0.5)
        if open_ports > 5:
            queue1.append(ip)
        elif 0 < open_ports < 5:
            queue2.append(ip)
        elif open_ports == 0:
            queue3.append(ip)
        else:
            queue4.append(ip)

def scan_other(ips: list[str]) -> None:
    nm = nmap.PortScanner()
    for ip in ips:
        open_ports = 0
        for port in other_ports:
            res = nm.scan(ip, str(port))
            if res["scan"]:
                if res["scan"][ip]["tcp"][port]["state"] == "open":
                    open_ports += 1
                    data = [ip, port, datetime.datetime.now(), "Y"]
                    writer.writerow(data)

def write_csv_header(writer: csv.writer) -> None:
    data = ["ip", "port", "timestamp", "open"]
    writer.writerow(data)

if __name__ == "__main__":
    random.seed(time.time_ns())
    f = open("scan_results.csv", "w")
    writer = csv.writer(f)
    write_csv_header(writer)
    ip_list_shuffled = get_ip_range_suffled("31.209.224.0/20")#sys.argv[1])
    scan_most_common(ip_list_shuffled, writer)
    scan_other(queue1)
    scan_other(queue2)
    scan_other(queue3)
    scan_other(queue4)
