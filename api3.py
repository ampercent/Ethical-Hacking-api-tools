import argparse
import socket
import asyncio
import aiohttp
import concurrent.futures
from urllib.parse import urlparse, urljoin
import threading
import time
import requests

# Helper functions for Port Scanning
def get_ip(url):
    try:
        domain = urlparse(url).hostname
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error resolving IP: {e}"

def scan_port(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        s.close()
        return port, "Open"
    except:
        return port, "Closed"

def port_scan(ip):
    open_ports = []
    ports = range(1, 1025)  # Scan ports from 1 to 1024
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, status = future.result()
            if status == "Open":
                open_ports.append(port)
    return open_ports

# Helper functions for API Enumeration
async def check_endpoint(session, base_url, endpoint):
    try:
        url = urljoin(base_url, endpoint)
        async with session.get(url, timeout=3) as response:
            if response.status == 200:
                return endpoint, "Found"
            return endpoint, "Not Found"
    except:
        return endpoint, "Error"

async def enumerate_api_endpoints(base_url):
    endpoints = ["/login", "/admin", "/user", "/register", "/api/v1", "/api/v2"]
    async with aiohttp.ClientSession() as session:
        tasks = [check_endpoint(session, base_url, endpoint) for endpoint in endpoints]
        results = await asyncio.gather(*tasks)
    return {endpoint: status for endpoint, status in results}

# Check HTTP Connection
def test_connection(url):
    try:
        response = requests.get(url, timeout=3)
        return response.status_code
    except requests.exceptions.RequestException as e:
        return f"Connection Error: {e}"

# Verbose Mode - Detailed Output
def verbose_mode(url, ip, ports, connection_status, enum_results, report_file=None):
    print(f"\n[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] API Enumeration Results:")
    for endpoint, status in enum_results.items():
        print(f"   {endpoint}: {status}")
    
    if report_file:
        with open(report_file, 'a') as f:
            f.write(f"\n{url}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Ports: {', '.join(map(str, ports))}\n")
            f.write(f"Connection: {connection_status}\n")
            f.write(f"API Endpoints: {', '.join([f'{k}: {v}' for k, v in enum_results.items()])}\n")
            f.write("\n" + "-"*50 + "\n")

# Normal Mode - Summary Output
def normal_mode(url, ip, ports, connection_status, enum_results, report_file=None):
    print(f"[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] API Enumeration Results: {', '.join([f'{k}: {v}' for k, v in enum_results.items()])}")
    
    if report_file:
        with open(report_file, 'a') as f:
            f.write(f"\n{url}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Ports: {', '.join(map(str, ports))}\n")
            f.write(f"Connection: {connection_status}\n")
            f.write(f"API Endpoints: {', '.join([f'{k}: {v}' for k, v in enum_results.items()])}\n")
            f.write("\n" + "-"*50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Fast Port Scanning and API Enumeration Tool")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://domain/api/user/1)")
    parser.add_argument("--mode", choices=["normal", "verbose", "brief"], default="normal", help="Output mode")
    parser.add_argument("--report", help="Save the report to a file")
    args = parser.parse_args()

    url = args.url
    mode = args.mode
    report_file = args.report

    print(f"[+] Targeting: {url}")

    # Step 1: Get IP Address
    ip = get_ip(url)
    print(f"[+] Resolving IP: {ip}")

    # Step 2: Scan Open Ports
    print(f"[+] Scanning ports from 1 to 1024...")
    open_ports = port_scan(ip)

    # Step 3: Check Connection
    connection_status = test_connection(url)

    # Step 4: Enumerate API Endpoints (async)
    print(f"[+] Enumerating API endpoints...")
    enum_results = asyncio.run(enumerate_api_endpoints(url))

    # Output based on mode
    if mode == "verbose":
        verbose_mode(url, ip, open_ports, connection_status, enum_results, report_file)
    elif mode == "normal":
        normal_mode(url, ip, open_ports, connection_status, enum_results, report_file)
    else:  # brief mode (only key details)
        print(f"[+] URL: {url}")
        print(f"[+] IP: {ip}")
        print(f"[+] Ports: {', '.join(map(str, open_ports))}")
        print(f"[+] Connection: {connection_status}")
        print(f"[+] API Endpoints: {', '.join([f'{k}: {v}' for k, v in enum_results.items()])}")

if __name__ == "__main__":
    main()
