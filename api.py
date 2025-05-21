import argparse
import socket
import requests
from urllib.parse import urlparse

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
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((ip, port))
            open_ports.append(port)
        except:
            pass
        s.close()
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
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException as e:
        return f"Connection Error: {e}"

# OWASP API Testing: API1 (Broken Object Level Authorization)
def test_bola(base_url):
    try:
        response1 = requests.get(base_url + "/1")
        response2 = requests.get(base_url + "/2")
        if response1.status_code == 200 and response2.status_code == 200:
            return "[!] Potential BOLA: /2 returned 200"
        return "[+] No BOLA detected"
    except Exception as e:
        return f"[!] BOLA test failed: {e}"

# Verbose Mode - Detailed Output
def verbose_mode(url, ip, ports, details, connection_status, bola_test):
    print(f"\n[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print("\n[+] Port Details:")
    for port, status in details.items():
        print(f"   Port {port}: {status}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] OWASP API1 - BOLA Test: {bola_test}")

# Normal Mode - Summary Output
def normal_mode(url, ip, ports, connection_status, bola_test):
    print(f"[+] URL: {url}")
    print(f"[+] IP Address: {ip}")
    print(f"[+] Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
    print(f"[+] Connection Status: {connection_status}")
    print(f"[+] OWASP API1 - BOLA Test: {bola_test}")

def main():
    parser = argparse.ArgumentParser(description="Minimal API & Web Security CLI Tool")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://domain/api/user/1)")
    parser.add_argument("--mode", choices=["normal", "verbose", "brief"], default="normal", help="Output mode")
    args = parser.parse_args()

    url = args.url
    mode = args.mode

    print(f"[+] Targeting: {url}")

    # Step 1: Get IP Address
    ip = get_ip(url)
    print(f"[+] Resolving IP: {ip}")

    # Step 2: Scan Open Ports
    ports = port_scan(ip)
    details = get_port_details(ip, ports)

    # Step 3: Check Connection
    connection_status = test_connection(url)

    # Step 4: OWASP API Test (API1 - BOLA)
    bola_test = test_bola(url.rsplit('/', 1)[0])

    # Output based on mode
    if mode == "verbose":
        verbose_mode(url, ip, ports, details, connection_status, bola_test)
    elif mode == "normal":
        normal_mode(url, ip, ports, connection_status, bola_test)
    else:  # brief mode (only key details)
        print(f"[+] URL: {url}")
        print(f"[+] IP: {ip}")
        print(f"[+] Ports: {', '.join(map(str, ports))}")
        print(f"[+] Connection: {connection_status}")
        print(f"[+] BOLA Test: {bola_test}")

if __name__ == "__main__":
    main()

