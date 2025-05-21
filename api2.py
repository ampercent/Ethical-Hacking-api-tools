import argparse
import socket
import requests
from urllib.parse import urlparse, urljoin
import time
import os
import logging

# Helper functions
def get_ip(url):
    try:
        domain = urlparse(url).hostname
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        return f"Error resolving IP: {e}"

def port_scan(ip, ports=[80, 443, 8080, 8443]):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

def get_port_details(ip, ports):
    details = {}
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            details[port] = "Open"
            s.close()
        except:
            details[port] = "Closed"
    return details

def test_connection(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code
    except requests.exceptions.RequestException as e:
        return f"Connection Error: {e}"

# OWASP API Testing: API1 (BOLA)
def test_bola(base_url):
    try:
        # Test two different resources for BOLA (user IDs)
        response1 = requests.get(urljoin(base_url, "/user/1"))
        response2 = requests.get(urljoin(base_url, "/user/2"))
        if response1.status_code == 200 and response2.status_code == 200:
            return "[!] Potential BOLA: /user/2 returned 200"
        return "[+] No BOLA detected"
    except Exception as e:
        return f"[!] BOLA test failed: {e}"

# OWASP API Testing: API2 (Broken Authentication)
def test_broken_auth(base_url):
    try:
        # Test without authentication or with invalid token
        headers = {'Authorization': 'Bearer invalid_token'}
        response = requests.get(base_url, headers=headers)
        if response.status_code == 401:
            return "[+] Broken Authentication: Invalid token returns 401"
        return "[+] No Broken Authentication detected"
    except Exception as e:
        return f"[!] Broken Auth test failed: {e}"

# Rate Limiting Test (API4)
def test_rate_limiting(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    for _ in range(10):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 429:
                return "[!] Rate Limiting Detected: Too many requests"
            time.sleep(1)
        except requests.exceptions.RequestException as e:
            return f"[!] Rate Limiting test failed: {e}"
    return "[+] No Rate Limiting detected"

# Web Vulnerability: Path Traversal
def test_path_traversal(url):
    payload = "../etc/passwd"
    try:
        response = requests.get(url + "/" + payload)
        if "root:" in response.text:
            return "[!] Path Traversal Vulnerability Detected"
        return "[+] No Path Traversal detected"
    except Exception as e:
        return f"[!] Path Traversal test failed: {e}"

# Verbose Mode - Detailed Output
def verbose_mode(url, ip, ports, details, connection_status, bola_test, auth_test, rate_limit_test, path_traversal_test, report_file=None):
    print(f"\n[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print("\n[+] Port Details:")
    for port, status in details.items():
        print(f"   Port {port}: {status}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] OWASP API1 - BOLA Test: {bola_test}")
    print(f"[+] OWASP API2 - Broken Auth Test: {auth_test}")
    print(f"[+] OWASP API4 - Rate Limiting Test: {rate_limit_test}")
    print(f"[+] Web Vulnerability - Path Traversal Test: {path_traversal_test}")
    
    if report_file:
        with open(report_file, 'a') as f:
            f.write(f"\n{url}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Ports: {', '.join(map(str, ports))}\n")
            f.write(f"Connection: {connection_status}\n")
            f.write(f"BOLA: {bola_test}\n")
            f.write(f"Broken Auth: {auth_test}\n")
            f.write(f"Rate Limiting: {rate_limit_test}\n")
            f.write(f"Path Traversal: {path_traversal_test}\n")
            f.write("\n" + "-"*50 + "\n")

# Normal Mode - Summary Output
def normal_mode(url, ip, ports, connection_status, bola_test, auth_test, rate_limit_test, path_traversal_test, report_file=None):
    print(f"[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] BOLA Test: {bola_test}")
    print(f"[+] Broken Auth Test: {auth_test}")
    print(f"[+] Rate Limiting Test: {rate_limit_test}")
    print(f"[+] Path Traversal Test: {path_traversal_test}")
    
    if report_file:
        with open(report_file, 'a') as f:
            f.write(f"\n{url}\n")
            f.write(f"IP: {ip}\n")
            f.write(f"Ports: {', '.join(map(str, ports))}\n")
            f.write(f"Connection: {connection_status}\n")
            f.write(f"BOLA: {bola_test}\n")
            f.write(f"Broken Auth: {auth_test}\n")
            f.write(f"Rate Limiting: {rate_limit_test}\n")
            f.write(f"Path Traversal: {path_traversal_test}\n")
            f.write("\n" + "-"*50 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Enhanced API & Web Security CLI Tool")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://domain/api/user/1)")
    parser.add_argument("--mode", choices=["normal", "verbose", "brief"], default="normal", help="Output mode")
    parser.add_argument("--ports", type=int, nargs="*", default=[80, 443, 8080, 8443], help="List of ports to scan (e.g. 80 443 8080)")
    parser.add_argument("--report", help="Save the report to a file")
    args = parser.parse_args()

    url = args.url
    mode = args.mode
    ports = args.ports
    report_file = args.report

    print(f"[+] Targeting: {url}")

    # Step 1: Get IP Address
    ip = get_ip(url)
    print(f"[+] Resolving IP: {ip}")

    # Step 2: Scan Open Ports
    open_ports = port_scan(ip, ports)
    details = get_port_details(ip, open_ports)

    # Step 3: Check Connection
    connection_status = test_connection(url)

    # Step 4: OWASP API Tests
    bola_test = test_bola(url.rsplit('/', 1)[0])
    auth_test = test_broken_auth(url)
    rate_limit_test = test_rate_limiting(url)
    path_traversal_test = test_path_traversal(url)

    # Output based on mode
    if mode == "verbose":
        verbose_mode(url, ip, open_ports, details, connection_status, bola_test, auth_test, rate_limit_test, path_traversal_test, report_file)
    elif mode == "normal":
        normal_mode(url, ip, open_ports, connection_status, bola_test, auth_test, rate_limit_test, path_traversal_test, report_file)
    else:  # brief mode (only key details)
        print(f"[+] URL: {url}")
        print(f"[+] IP: {ip}")
        print(f"[+] Ports: {', '.join(map(str, open_ports))}")
        print(f"[+] Connection: {connection_status}")
        print(f"[+] BOLA: {bola_test}")

if __name__ == "__main__":
    main()

