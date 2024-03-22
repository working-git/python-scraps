#! /usr/bin/env python3

import argparse
import socket
import sys

def parse_arguments():
    """
    Parses command line arguments.
    """
    parser = argparse.ArgumentParser(description="Simple port scanner")
    parser.add_argument("target", help="Target host")
    parser.add_argument("port", help="Port range to scan")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--tcp", help="Use TCP", action="store_true")
    group.add_argument("-u", "--udp", help="Use UDP", action="store_true")
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")
    return parser.parse_args()

def validate_port_range(port_range):
    """
    Validates the provided port range and returns a list of ports to scan.
    """
    if "-" in port_range:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            sys.exit("Invalid port range. Ports must be between 0-65535 and start port must be less than end port.")
        return list(range(start_port, end_port + 1))
    else:
        port = int(port_range)
        if port < 0 or port > 65535:
            sys.exit("Invalid port. Port must be between 0-65535.")
        return [port]

def tcp_scan(target, port):
    """
    Performs a TCP scan on the specified port.
    Returns True if the port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        return result == 0

def udp_scan(target, port):
    """
    Performs a UDP scan on the specified port. Due to the nature of UDP, this may not be reliable.
    Returns True if the port is potentially open, False if definitely closed.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            sock.sendto(bytes(), (target, port))
            sock.recvfrom(512)
            return True
        except socket.timeout:
            return False


def update_progress_bar(total, progress):
    bar_length = 50 
    percent = float(progress) / total
    arrow = '-' * int(round(percent * bar_length)-1) + '>'
    spaces = ' ' * (bar_length - len(arrow))

    sys.stdout.write("\rProgress: [{0}] {1}%".format(arrow + spaces, int(round(percent * 100))))
    sys.stdout.flush()

def main():
    args = parse_arguments()
    ports_to_scan = validate_port_range(args.port)
    protocol = "UDP" if args.udp else "TCP"
    scan_func = udp_scan if args.udp else tcp_scan
    
    open_ports = []
    closed_ports = []
    
    print(f"Scanning {protocol} ports on {args.target}...")
    
    for i, port in enumerate(ports_to_scan, 1):
        if scan_func(args.target, port):
            open_ports.append(port)
        else:
            closed_ports.append(port)
        update_progress_bar(len(ports_to_scan), i)

    print("\n")
    
    if args.verbose:
        print(f"Number of open ports: {len(open_ports)}")
        print(f"Open ports: {open_ports}")
        print(f"Number of closed ports: {len(closed_ports)}")
        print(f"Closed ports: {closed_ports}")
    else:
        print(f"Open ports: {open_ports}")
        print(f"Number of closed ports: {len(closed_ports)}")

main()
