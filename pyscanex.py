#!/usr/bin/env python3
# ============================================================
# PyscanEx - Interactive TCP Port Scanner
#
# Description:
#   This program performs TCP port scanning for a single host
#   or a network in CIDR format (e.g. 192.168.1.0/24).
#
#   Features:
#     - Allows users to choose from 4 scan types (default, common, custom, all)
#     - Detects which ports are open or closed
#     - Displays results clearly in the console with colored output
#     - Optionally exports results to a CSV file
#
#   It uses socket.connect_ex() to test TCP connections.
#   Port scanning can be used for legitimate network assessment.
#   Always scan only authorized systems.
#
# ============================================================

# ---------- Import Required Libraries ----------
import socket      # for network communication
import time        # for measuring scan duration
import csv         # for CSV file handling
import ipaddress   # for IP and network manipulation

# ---------- Console Color Codes for Readable Output ----------
CSI = "\033["           # Escape sequence start
RESET = CSI + "0m"      # Reset color
BOLD = CSI + "1m"       # Bold text
GREEN = CSI + "32m"     # Green color for open ports
YELLOW = CSI + "33m"    # Yellow for info
RED = CSI + "31m"       # Red for closed ports
CYAN = CSI + "36m"      # Cyan for highlights

# ---------- UI Helper Functions ----------
def title(text): 
    # Displays section titles in bold and color
    print(f"{BOLD}{YELLOW}==={RESET} {text} {YELLOW}==={RESET}")

def info(text): 
    # Prints informational messages
    print(f"{YELLOW}[i]{RESET} {text}")

def success(text): 
    # Prints success messages (open ports)
    print(f"{GREEN}[open]{RESET} {text}")

def fail(text): 
    # Prints failed connections (closed ports)
    print(f"{RED}[closed]{RESET} {text}")

# ---------- Port Parsing Function ----------
def parse_ports(spec: str):
    # Converts a string like "22,80,8000-8010" into a list of ports
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            # Handle port ranges
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            # Validate range
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(a, b + 1))
        else:
            # Handle individual ports
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    # Return ports in ascending order
    return sorted(ports)

# ---------- Core Port Scanning Function ----------
def scan_port_once(target_ip: str, port: int, timeout: float = 0.8) -> bool:
    # Tests a single TCP port on a target IP using socket.connect_ex()
    # Returns True if port is open, False otherwise
    sock = None
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set timeout for the connection
        sock.settimeout(timeout)
        # Attempt connection; connect_ex returns 0 if successful
        rc = sock.connect_ex((target_ip, port))
        return rc == 0
    except Exception:
        # On any exception, assume port is closed
        return False
    finally:
        # Always close socket to free resources
        if sock:
            try:
                sock.close()
            except Exception:
                pass

# ---------- Service Name Resolver ----------
def try_get_service(port: int):
    # Attempts to retrieve a human-readable service name for the port
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        # Fallback to common port name dictionary
        return COMMON_PORT_NAMES.get(port, "")

# ---------- IP Range Scanner ----------
def scan_ip_range(ips, ports, timeout=0.4, show_progress=True):
    # Scans a list of IP addresses and ports
    # Yields (ip, port, is_open) for each result
    total = len(ips) * len(ports)
    if total == 0:
        return

    info(f"Range scan: {total} total tasks")
    scanned = 0
    last_percent = -1

    # Loop through all combinations of IPs and ports
    for ip in ips:
        for p in ports:
            try:
                is_open = scan_port_once(ip, p, timeout)
            except Exception:
                is_open = False

            scanned += 1
            # Display progress for large scans
            if show_progress and total > 20:
                percent = int(scanned / total * 100)
                if percent != last_percent and percent % 5 == 0:
                    info(f"Progress: {percent}% ({scanned}/{total})")
                    last_percent = percent
            
            # Yield result of each scan
            yield ip, p, is_open

# ---------- Target Expansion ----------
def expand_targets(spec: str):
    # Expands a single IP or CIDR into a list of IPs to scan
    s = spec.strip()
    parts = s.rstrip('.').split('.')
    # Interpret incomplete IPs like "192.168.1" as "192.168.1.0/24"
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        s = s.rstrip('.') + '.0/24'
    try:
        if '/' not in s:
            # Single IP
            ip = ipaddress.ip_address(s)
            return [str(ip)]
        else:
            # Network range (CIDR)
            net = ipaddress.ip_network(s, strict=False)
            return [str(h) for h in net.hosts()]
    except Exception as e:
        raise ValueError(f"Bad network/host specification: {e}")

# ---------- Common Ports Dictionary ----------
COMMON_PORTS = [20,21,22,23,25,53,67,68,69,80,110,111,123,137,138,139,143,
                161,162,179,389,443,445,465,514,520,587,631,993,995,1433,
                1521,1723,3306,3389,5900,8080]

COMMON_PORT_NAMES = {
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"domain",
    67:"dhcp",68:"dhcp",69:"tftp",80:"http",110:"pop3",123:"ntp",
    137:"netbios-ns",139:"netbios-ssn",143:"imap",161:"snmp",443:"https",
    3306:"mysql",3389:"ms-wbt-server",5900:"vnc",8080:"http-alt"
}

# ---------- CSV Export ----------
def export_to_csv(rows, filename):
    # Saves the scan results into a CSV file
    # Columns: ip, hostname, port, status, service
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['ip', 'hostname', 'port', 'status', 'service'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    info(f"Saved results to {filename}")

# ---------- Main Program ----------
def main():
    # Main function handling user input, scanning, and output
    title("PyscanEx - Interactive TCP Port Scanner")

    # User input for mode and target
    mode = input("Scan mode (host/net) [host]: ").strip().lower() or "host"
    target = input("Target (hostname/IP or network): ").strip()
    if not target:
        print("No target provided.")
        return

    # Resolve single host or expand network range
    if mode == "host":
        try:
            ip = socket.gethostbyname(target)
        except Exception as e:
            print(f"Could not resolve {target}: {e}")
            return
        ips = [ip]
        info(f"Resolved {target} -> {ip}")
    else:
        ips = expand_targets(target)
        info(f"Expanded network -> {len(ips)} hosts ({ips[0]} - {ips[-1]})")

    # Port scan mode selection
    print("\nChoose scan type:")
    print("  1) Default: TCP port 80")
    print("  2) Common ports")
    print("  3) Custom ports")
    print("  4) All ports (1–65535)")
    choice = input("Your choice [1-4]: ").strip()

    # Select appropriate port list and timeout
    if choice == "1":
        ports, timeout = [80], 0.8
    elif choice == "2":
        ports, timeout = COMMON_PORTS, 0.8
    elif choice == "3":
        spec = input("Enter ports (e.g., 22,80,8000-8010): ").strip()
        ports = parse_ports(spec)
        timeout = 1.0
    elif choice == "4":
        confirm = input(f"{RED}Scan all 65535 ports? {YELLOW}(y/N): {RESET}").lower()
        if confirm != "y": 
            return
        ports, timeout = list(range(1,65536)), 0.35
    else:
        print("Invalid choice.")
        return

    # Ask whether to export results to CSV
    do_csv = input("Export results to CSV? (y/N): ").lower() == "y"
    csv_name = input("CSV filename [scan_results.csv]: ").strip() or "scan_results.csv" if do_csv else None

    # Start scan
    info(f"Starting scan: {len(ips)} host(s) × {len(ports)} port(s)")
    start = time.time()

    # Initialize storage variables
    results, open_records, seen = [], [], set()
    hostname_cache = {}

    # Perform the scan
    for ip, port, is_open in scan_ip_range(ips, ports, timeout=timeout):
        svc = try_get_service(port)
        status = "open" if is_open else "closed"
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)

        hostname = hostname_cache.get(ip, "")

        # Resolve hostname for open ports only
        if is_open:
            if not hostname:
                hostname = "Unknown"
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                hostname_cache[ip] = hostname
                print(f"{ip:<18} - {hostname}")
            success(f"{ip}:{port} ({svc})")
            open_records.append({'ip': ip, 'hostname': hostname, 'port': port,
                                 'status': status, 'service': svc})
        elif len(ips) == 1 and len(ports) <= 10:
            fail(f"{ip}:{port} closed")

        results.append({'ip': ip, 'hostname': hostname, 'port': port,
                        'status': status, 'service': svc})

    # Calculate total scan time
    elapsed = time.time() - start

    # Display scan summary
    title("Scan summary")
    if open_records:
        info(f"Found {len(open_records)} open ports:")
        for r in sorted(open_records, key=lambda x: (x['ip'], x['port'])):
            success(f"{r['ip']} ({r['hostname']}):{r['port']} ({r['service']})")
    else:
        info("No open TCP ports found.")
    info(f"Elapsed: {elapsed:.2f} seconds")

    # Save to CSV if requested
    if do_csv:
        sorted_rows = sorted(results, key=lambda r: (0 if r['status']=="open" else 1, r['ip'], int(r['port'])))
        export_to_csv(sorted_rows, csv_name)

# ---------- Entry Point ----------
# Executes the main() function when run directly
if __name__ == "__main__":
    main()
