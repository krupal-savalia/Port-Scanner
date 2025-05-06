# Port Scanner with Vulnerability Assessment

This is a Python-based tool that scans a given host for open ports, detects basic services, and matches known vulnerabilities from a local JSON database.

## 🚀 Features
- Scans top 1000 TCP ports
- Basic service detection
- Uses Nmap for version detection
- Grabs service banners
- Pulls latest CVEs from NVD API
- Generates an HTML report

## 📁 Project Structure
```
port-scanner/
├── scanner.py            # Main script
├── common_ports.txt      # Port-service map
├── vulndb.json           # Vulnerability database
├── README.md
```

## 📦 Requirements
```bash
pip install requests
sudo apt install nmap   # Required for service version detection
```

## 🔧 Usage
```bash
python scanner.py <target-host>
```

## 🧪 Output Example
```
- Port status
- Banner
- CVE list from NVD
- HTML report with full results
```

## 📌 Author
Krupal Savaliya
