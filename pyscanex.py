#!/usr/bin/env python3
# ============================================================
# PyscanEx - Interactive TCP Port Scanner
#
# Description:
#   This program performs TCP port scanning for a single host
#   or a network in CIDR format (e.g. 192.168.1.0/24).
#
#   It allows users to:
#     - Choose from 4 scan types (default, common, custom, all)
#     - Detect which ports are open or closed
#     - Display results clearly in the console
#     - Optionally export results to a CSV file
#
#   It uses socket.connect_ex() to attempt TCP connections 
#
# ============================================================


import socket
import time
import csv
import ipaddress

# ---------- UI helpers ----------
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def title(text): print(f"{BOLD}{YELLOW}==={RESET} {text} {YELLOW}==={RESET}")
def info(text): print(f"{YELLOW}[i]{RESET} {text}")
def success(text): print(f"{GREEN}[open]{RESET} {text}")
def fail(text): print(f"{RED}[closed]{RESET} {text}")

# ---------- Port parsing ----------

# This function parses a port specification string into a list of ports.
# Example input: "22,80,8000-8010"
def parse_ports(spec: str):
    ports = set()
    # Split by commas and process each part
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        # Handle ranges
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"Invalid range: {part}")
            ports.update(range(a, b + 1))
        else:
            # Handle single port
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    return sorted(ports)

# ---------- Core port scanner ----------
def scan_port_once(target_ip: str, port: int, timeout: float = 0.8) -> bool:
    # This funcion scans a single TCP port on the target IP address.
    # Return True if TCP port is open.
    sock = None
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((target_ip, port))
        # If rc is 0, the port is open
        return rc == 0
    except Exception:
        return False
    finally:
        if sock:
            try:
                # Close the socket
                sock.close()
            except Exception:
                pass

def try_get_service(port: int):
    # Return service name for a given TCP port.
    try:
        # Use socket library to get service name
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return COMMON_PORT_NAMES.get(port, "")

# ---------- IP range scanner ----------
def scan_ip_range(ips, ports, timeout=0.4, show_progress=True):
    # Scan a range of IPs and ports.
    total = len(ips) * len(ports)
    if total == 0:
        return

    info(f"Range scan: {total} total tasks")
    scanned = 0
    last_percent = -1

    # Iterate over all IPs and ports
    for ip in ips:
        for p in ports:
            try:
                # Scan the port
                is_open = scan_port_once(ip, p, timeout)
            except Exception:
                # On error, assume port is closed
                is_open = False

            scanned += 1
            # Show progress if enabled
            if show_progress and total > 20:
                percent = int(scanned / total * 100)
                # print progress every 5%
                if percent != last_percent and percent % 5 == 0:
                    info(f"Progress: {percent}% ({scanned}/{total})")
                    last_percent = percent
            
            yield ip, p, is_open

# ---------- Target expansion ----------
def expand_targets(spec: str):
    # Return a list of host IPs from a single address or CIDR.
    s = spec.strip()
    parts = s.rstrip('.').split('.')
    
    # Handle incomplete IPs like "192.168.1" as /24 networks
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        s = s.rstrip('.') + '.0/24'
    try:
        # Check if it's a single IP or a network
        if '/' not in s:
            ip = ipaddress.ip_address(s)
            return [str(ip)]
        net = ipaddress.ip_network(s, strict=False)
        return [str(h) for h in net.hosts()]
    except Exception as e:
        raise ValueError(f"Bad network/host specification: {e}")

# ---------- Common ports ----------
COMMON_PORTS = [20,21,22,23,25,53,67,68,69,80,110,111,123,137,138,139,143,
                161,162,179,389,443,445,465,514,520,587,631,993,995,1433,
                1521,1723,3306,3389,5900,8080]
COMMON_PORT_NAMES = {
    20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"domain",
    67:"dhcp",68:"dhcp",69:"tftp",80:"http",110:"pop3",123:"ntp",
    137:"netbios-ns",139:"netbios-ssn",143:"imap",161:"snmp",443:"https",
    3306:"mysql",3389:"ms-wbt-server",5900:"vnc",8080:"http-alt"
}

# ---------- CSV export ----------
def export_to_csv(rows, filename):
    # Export scan results to a CSV file.
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['ip', 'hostname', 'port', 'status', 'service'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    info(f"Saved results to {filename}")

# ---------- Main ----------
def main():
    title("PyscanEx - Interactive TCP Port Scanner")

    mode = input("Scan mode (host/net) [host]: ").strip().lower() or "host"
    target = input("Target (hostname/IP or network): ").strip()
    if not target:
        print("No target provided.")
        return

    # Resolve or expand
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

    # Port selection
    print("\nChoose scan type:")
    print("  1) Default: TCP port 80")
    print("  2) Common ports")
    print("  3) Custom ports")
    print("  4) All ports (1–65535)")
    choice = input("Your choice [1-4]: ").strip()

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
        if confirm != "y": return
        ports, timeout = list(range(1,65536)), 0.35
    else:
        print("Invalid choice.")
        return

    do_csv = input("Export results to CSV? (y/N): ").lower() == "y"
    csv_name = input("CSV filename [scan_results.csv]: ").strip() or "scan_results.csv" if do_csv else None

    # Scan
    info(f"Starting scan: {len(ips)} host(s) × {len(ports)} port(s)")
    start = time.time()

    # This will hold all results
    results, open_records, seen = [], [], set()
    hostname_cache = {}

    total_tasks = len(ips) * len(ports)

    # This performs the actual scanning
    for ip, port, is_open in scan_ip_range(ips, ports, timeout=timeout):
        svc = try_get_service(port)
        status = "open" if is_open else "closed"
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)

        hostname = hostname_cache.get(ip, "")

        # Inline hostname resolution only for open ports
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

    elapsed = time.time() - start

    # Summary
    title("Scan summary")
    if open_records:
        info(f"Found {len(open_records)} open ports:")
        # Sort and display open ports
        for r in sorted(open_records, key=lambda x: (x['ip'], x['port'])):
            success(f"{r['ip']} ({r['hostname']}):{r['port']} ({r['service']})")
    else:
        info("No open TCP ports found.")
    info(f"Elapsed: {elapsed:.2f} seconds")

    # CSV export
    if do_csv:
        sorted_rows = sorted(results, key=lambda r: (0 if r['status']=="open" else 1, r['ip'], int(r['port'])))
        export_to_csv(sorted_rows, csv_name)

# ---------- Entry point ----------
if __name__ == "__main__":
    main()
