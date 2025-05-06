import socket
import json
import sys

def load_ports(filename='common_ports.txt'):
    ports = {}
    with open(filename, 'r') as f:
        for line in f:
            if line.strip():
                port, service = line.strip().split(":")
                ports[int(port)] = service
    return ports

def load_vulndb(filename='vulndb.json'):
    with open(filename, 'r') as f:
        return json.load(f)

def scan_ports(target_ip, ports):
    open_ports = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports[port] = ports[port]
        sock.close()
    return open_ports

def check_vulnerabilities(open_ports, vulndb):
    for port, service in open_ports.items():
        print(f"\n[+] Port {port} is OPEN | Service: {service}")
        if service in vulndb:
            for vuln in vulndb[service]:
                print(f"    ⚠ CVE: {vuln['cve']} - {vuln['description']}")
        else:
            print("    No known vulnerabilities.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target-ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"🔍 Scanning {target}...\n")

    ports = load_ports()
    vulndb = load_vulndb()

    open_ports = scan_ports(target, ports)
    check_vulnerabilities(open_ports, vulndb)
