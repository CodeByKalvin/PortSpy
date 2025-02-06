import socket
import threading
import csv
import json
from queue import Queue
from datetime import datetime
from fpdf import FPDF
from scapy.all import sr1, IP, TCP
from pythonping import ping
import requests

print("CodeByKalvin")

# Dictionary of common ports and services
common_ports = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP Proxy"
}

# Store detected open ports
open_ports_info = []

# Lock object for thread safety
print_lock = threading.Lock()

# Function to check if the host is alive (ping or fallback to TCP)
def is_host_alive(ip, timeout=2):
    try:
        # Attempt ICMP ping
        response = ping(ip, count=3, timeout=timeout)
        if response.success():
            return True
        
        # Fallback to TCP check on port 80 (HTTP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, 80)) == 0
    except Exception as e:
        print(f"Error checking host availability: {e}")
        return False

# Function to detect the operating system using Scapy (with fallback for routers/gateways)
def detect_os(ip):
    try:
        # Send SYN packet to port 80
        ans = sr1(IP(dst=ip) / TCP(dport=80, flags="S"), timeout=3, verbose=0)
        if ans:
            ttl = ans.ttl
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            return "Unknown OS"
        else:
            # Fallback: Check if DNS port (53) is open for routers
            if sr1(IP(dst=ip) / TCP(dport=53, flags="S"), timeout=2, verbose=0):
                return "Router/Gateway"
            return "No response (Host unreachable)"
    except Exception as e:
        return f"OS detection failed: {e}"

# Function to grab service banners from open ports
def grab_banner(sock):
    try:
        sock.send(b'HEAD / HTTP/1.1\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8').strip()
        return "Non-standard HTTP response" if "<" in banner else banner or "No banner available"
    except Exception as e:
        return f"Error grabbing banner: {e}"

# CVE Vulnerability Lookup (mock or real API)
def cve_vulnerability_lookup(service, version):
    try:
        api_key = "YOUR_NVD_API_KEY"
        headers = {"apiKey": api_key, "Content-Type": "application/json"}
        query = f"{service} {version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={query}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200 and response.json().get("result", {}).get("CVE_Items"):
            cve_data = response.json()["result"]["CVE_Items"][0]
            cve = cve_data["cve"]["CVE_data_meta"]["ID"]
            description = cve_data["cve"]["description"]["description_data"][0]["value"]
            return f"{cve}: {description}"
        return "No known vulnerabilities found"
    except Exception as e:
        return f"Error during CVE lookup: {e}"

# Function to scan a single TCP port
def scan_port_tcp(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service_name = common_ports.get(port, "Unknown Service")
                banner = grab_banner(sock)
                version = banner.split(" ")[0] if banner else "Unknown"
                vulnerability = cve_vulnerability_lookup(service_name, version)
                with print_lock:
                    print(f"[+] Port {port} open (Service: {service_name}, Banner: {banner}, Vulnerability: {vulnerability})")
                    open_ports_info.append({
                        "ip": ip,
                        "port": port,
                        "service": service_name,
                        "banner": banner,
                        "vulnerability": vulnerability
                    })
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Function to handle multi-threaded port scanning
def threader(ip, port_queue, timeout):
    while True:
        port = port_queue.get()
        scan_port_tcp(ip, port, timeout)
        port_queue.task_done()

# Progress indicator for scans
def progress_bar(current, total):
    print(f"\rProgress: {current}/{total} ({(current / total) * 100:.2f}%)", end="")

# Main function to handle IP scanning
def port_scanner(ip, port_range=(1, 1024), num_threads=100, timeout=2):
    print(f"\nStarting scan on {ip} ({port_range[0]}-{port_range[1]}).")
    detected_os = detect_os(ip)
    print(f"Detected OS: {detected_os}")

    port_queue = Queue()
    total_ports = port_range[1] - port_range[0] + 1
    scanned_ports = 0

    for _ in range(num_threads):
        threading.Thread(target=threader, args=(ip, port_queue, timeout), daemon=True).start()

    for port in range(port_range[0], port_range[1] + 1):
        port_queue.put(port)
        scanned_ports += 1
        progress_bar(scanned_ports, total_ports)

    port_queue.join()
    print("\nScan complete.")

# Function to scan a range of IPs
def scan_ip_range(start_ip, end_ip, port_range=(1, 1024), num_threads=100, timeout=2):
    print(f"Scanning IP range: {start_ip} - {end_ip}")
    start_parts = list(map(int, start_ip.split(".")))
    end_parts = list(map(int, end_ip.split(".")))

    for i in range(start_parts[3], end_parts[3] + 1):
        ip = f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{i}"
        if is_host_alive(ip):
            print(f"Host {ip} is alive. Scanning...")
            port_scanner(ip, port_range, num_threads, timeout)
        else:
            print(f"Host {ip} is not alive. Skipping.")

# Function to save results to CSV, JSON, or PDF
def save_results(format='csv', filename='scan_results'):
    if format == 'csv':
        with open(f"{filename}.csv", 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=["ip", "port", "service", "banner", "vulnerability"])
            writer.writeheader()
            writer.writerows(open_ports_info)
    elif format == 'json':
        with open(f"{filename}.json", 'w', encoding='utf-8') as file:
            json.dump(open_ports_info, file, indent=4)
    elif format == 'pdf':
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Port Scan Report", ln=True, align="C")
        for info in open_ports_info:
            pdf.cell(200, 10, txt=f"IP: {info['ip']}, Port: {info['port']}, Service: {info['service']}, Banner: {info['banner']}, Vulnerability: {info['vulnerability']}", ln=True)
        pdf.output(f"{filename}.pdf")
    print(f"Results saved to {filename}.{format}")

# Main entry point
if __name__ == "__main__":
    print("Welcome to PortSpy - A Fast Network Scanner")
    scan_mode = input("Choose scan mode: (1) Quick Scan (1-1024) or (2) Full Scan (1-65535): ")
    port_range = (1, 1024) if scan_mode == '1' else (1, 65535)

    ip_mode = input("Scan (1) Single IP or (2) IP Range? ")
    if ip_mode == '1':
        target_ip = input("Enter target IP: ")
        if is_host_alive(target_ip):
            port_scanner(target_ip, port_range)
        else:
            print(f"Host {target_ip} is not alive. Exiting.")
    elif ip_mode == '2':
        start_ip = input("Enter start IP: ")
        end_ip = input("Enter end IP: ")
        scan_ip_range(start_ip, end_ip, port_range)

    save_choice = input("Save results? (csv/json/pdf): ").lower()
    save_results(save_choice)
