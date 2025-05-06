import socket
import subprocess
import json
import threading
import requests
import sys
from datetime import datetime

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
vuln_results = []

def banner_grab(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            return s.recv(1024).decode().strip()
    except:
        return "N/A"

def get_cves(service_name):
    try:
        response = requests.get(f"{NVD_API_URL}?keywordSearch={service_name}&resultsPerPage=2")
        data = response.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]
            cves.append((cve_id, desc))
        return cves
    except:
        return []

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = banner_grab(ip, port).lower()
            service = "unknown"
            if "apache" in banner:
                service = "apache"
            elif "ssh" in banner:
                service = "openssh"
            print(f"[+] Port {port} OPEN | Banner: {banner}")
            cves = get_cves(service) if service != "unknown" else []
            vuln_results.append({
                "port": port,
                "banner": banner,
                "service": service,
                "cves": cves
            })
        s.close()
    except Exception as e:
        pass

def run_scan(ip):
    threads = []
    print(f"Starting scan on {ip}...")
    for port in range(20, 1025):
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

def os_detection(ip):
    try:
        output = subprocess.check_output(["nmap", "-O", ip], universal_newlines=True)
        for line in output.splitlines():
            if "OS details" in line:
                return line.strip()
    except:
        return "OS detection failed."
    return "No OS info found."

def save_report(ip, os_info):
    report_path = f"report_{ip.replace('.', '_')}.html"
    with open(report_path, "w") as f:
        f.write(f"<html><head><title>VAPT Report</title></head><body>")
        f.write(f"<h1>VAPT Report for {ip}</h1>")
        f.write(f"<p><b>Date:</b> {datetime.now()}</p>")
        f.write(f"<p><b>OS Info:</b> {os_info}</p><hr>")
        for item in vuln_results:
            f.write(f"<h3>Port: {item['port']}</h3>")
            f.write(f"<p><b>Banner:</b> {item['banner']}</p>")
            f.write(f"<p><b>Service:</b> {item['service']}</p>")
            if item['cves']:
                f.write("<ul>")
                for cve in item['cves']:
                    f.write(f"<li><b>{cve[0]}</b>: {cve[1]}</li>")
                f.write("</ul>")
            else:
                f.write("<p>No known CVEs found.</p>")
            f.write("<hr>")
        f.write("</body></html>")
    print(f"✅ Report saved to {report_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target-ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    os_info = os_detection(target_ip)
    print(f"OS Detected: {os_info}")
    run_scan(target_ip)
    save_report(target_ip, os_info)
