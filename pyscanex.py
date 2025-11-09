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
#   It uses socket.connect_ex() to attempt TCP connections and
#   ThreadPoolExecutor for concurrent scanning.
#
# ============================================================

import socket
import time
import csv
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- UI helpers (for colored terminal output) ----------
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def title(text):
    # Print a bold cyan section title
    print(f"{BOLD}{CYAN}=== {text} ==={RESET}")

def info(text):
    # Print informational message in yellow
    print(f"{YELLOW}[i]{RESET} {text}")

def success(text):
    # Print success/open port message in green
    print(f"{GREEN}[open]{RESET} {text}")

def fail(text):
    # Print closed port message in red
    print(f"{RED}[closed]{RESET} {text}")

# ---------- Port parsing ----------
def parse_ports(spec: str):
    # Convert a string like "22,80,8000-8005" into a list of valid ports
    # Accepts comma-separated ports and inclusive ranges
    # Validates each port number (1–65535)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            # Range format "a-b"
            a, b = part.split("-", 1)
            try:
                a = int(a); b = int(b)
            except ValueError:
                raise ValueError(f"Invalid range: {part}")
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"Invalid range boundaries: {part}")
            ports.update(range(a, b + 1))
        else:
            # Single port number
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: {part}")
            if p < 1 or p > 65535:
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    return sorted(ports)

# ---------- Scanner core ----------
def scan_port_once(target_ip: str, port: int, timeout: float = 0.8) -> bool:
    # Try connecting once to (target_ip, port)
    # Uses socket.connect_ex():
    #   - Returns 0 if the connection succeeds (port is OPEN)
    #   - Non-zero or exception means port is CLOSED
    # A short timeout is used to avoid waiting too long for each host
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        rc = sock.connect_ex((target_ip, port))
        return rc == 0
    except Exception:
        # Any socket error or exception is treated as "closed"
        return False
    finally:
        # Always close socket to avoid resource leaks
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

def try_get_service(port: int):
    # Try the system service database first, explicitly for TCP.
    # If that fails, fall back to a small built-in mapping of common ports.
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return COMMON_PORT_NAMES.get(port, "")


# ---------- Multi-target scanning ----------
def scan_ip_range(ips, ports, timeout=0.8, max_workers=200, show_progress=True):
    # Scan all (ip, port) pairs concurrently
    # Uses ThreadPoolExecutor for multi-threaded network scanning
    # Prints coarse progress updates (every ~5%) to show scan progress
    total = len(ips) * len(ports)
    if total == 0:
        return

    # Adjust number of threads (never exceed total tasks or max_workers)
    workers = min(max_workers, max(4, total))
    info(f"Using up to {workers} worker threads for {total} tasks")
    scanned = 0
    last_percent = -1

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        # Submit one scan task for each (ip, port)
        for ip in ips:
            for p in ports:
                fut = ex.submit(scan_port_once, ip, p, timeout)
                futures[fut] = (ip, p)

        # Process results as they finish
        for fut in as_completed(futures):
            ip, p = futures[fut]
            try:
                is_open = fut.result()
            except Exception:
                # If a worker fails, treat the port as closed
                is_open = False

            scanned += 1
            # Update progress every 5% for large scans
            if show_progress and total > 20:
                percent = int(scanned / total * 100)
                if percent != last_percent and percent % 5 == 0:
                    info(f"Progress: {percent}% ({scanned}/{total})")
                    last_percent = percent

            yield ip, p, is_open

# ---------- Target expansion ----------
def expand_targets(spec: str, max_hosts_warn: int = 4096):
    # Convert user input into a list of host IPs
    # Supports:
    #   - Single IP (e.g., "192.168.1.10")
    #   - CIDR (e.g., "192.168.1.0/24", "10.0.0.0/16")
    #   - Shorthand (e.g., "192.168.1") → treated as /24
    #
    # Returns a list of usable host IPs (skips network & broadcast)
    s = spec.strip()

    # Treat "a.b.c" as shorthand for "a.b.c.0/24"
    parts = s.rstrip('.').split('.')
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        s = s.rstrip('.') + '.0/24'

    try:
        if '/' not in s:
            # Single host case
            ip = ipaddress.ip_address(s)
            if ip.version != 4:
                raise ValueError("Only IPv4 supported.")
            return [str(ip)]
        # Network range (CIDR format)
        net = ipaddress.ip_network(s, strict=False)
    except Exception as e:
        raise ValueError(f"Bad network/host specification: {e}")

    # Get usable host IPs (skip network/broadcast)
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        raise ValueError("Network has no usable hosts.")

    # Warn user later if host list is very large (> max_hosts_warn)
    return hosts

# ---------- Common ports ----------
# A list of typical TCP ports used for common services
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,111,123,137,138,139,143,161,162,
    179,389,443,445,465,514,520,587,631,993,995,1433,1521,1723,3306,3389,5900,8080
]

# Mapping of common port numbers to service names
COMMON_PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp", 68: "dhcp", 69: "tftp",
    80: "http", 110: "pop3", 123: "ntp", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 443: "https",
    3306: "mysql", 3389: "ms-wbt-server", 5900: "vnc",
    8080: "http-alt"
}


# ---------- CSV export ----------
def export_to_csv(rows, filename):
    # Save scan results to a CSV file for later analysis
    # Each row contains: IP, port, status, service
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['ip', 'port', 'status', 'service'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    info(f"Saved results to {filename}")

# ---------- Main interactive flow ----------
def main():
    # Print program title
    title("PyscanEx - Interactive TCP Port Scanner")

    # Prompt user for scan mode
    mode = input("Scan mode - single host or network (CIDR format, e.g. 192.168.1.0/28)? (host/net) [host]: ").strip().lower() or "host"
    if mode not in ('host', 'net'):
        print("Invalid mode. Use 'host' or 'net'. Exiting.")
        return

    # Ask for target input
    target = input("Target (hostname/IP or network prefix): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return

    # Determine list of IPs to scan
    ips = []
    if mode == 'host':
        # Resolve hostname to IP
        try:
            target_ip = socket.gethostbyname(target)
        except Exception as e:
            print(f"Could not resolve {target}: {e}")
            return
        ips = [target_ip]
        info(f"Resolved {target} -> {target_ip}")
    else:
        # Expand network to host list
        try:
            ips = expand_targets(target)
            if len(ips) > 4096:
                ans = input(f"Scanning {len(ips)} hosts is large. Continue? (y/N): ").strip().lower()
                if ans != 'y':
                    print("Cancelled.")
                    return
        except Exception as e:
            print(f"Bad network prefix: {e}")
            return
        count = len(ips)
        info(f"Expanded network -> {count} hosts ({ips[0]} - {ips[-1]})")

    # Prompt for scan type
    print()
    print("Choose scan type:")
    print("  1) Default: TCP port 80")
    print("  2) Common ports (typical services)")
    print("  3) Custom ports (e.g. 22,80,8000-8010)")
    print("  4) All ports (1-65535)")
    choice = input("Your choice [1-4]: ").strip()

    # Configure scan parameters based on user choice
    if choice == "1":
        ports = [80]
        timeout = 0.8
    elif choice == "2":
        ports = COMMON_PORTS
        timeout = 0.8
    elif choice == "3":
        spec = input("Enter ports (comma/ranges): ").strip()
        try:
            ports = parse_ports(spec)
        except ValueError as e:
            print(f"Bad port specification: {e}")
            return
        timeout = 1.0  # Slightly longer timeout for custom scans
    elif choice == "4":
        confirm = input(f"{RED}Scan all 65535 TCP ports on each host? This is heavy. {YELLOW}Proceed? (y/N): {RESET}").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
        ports = list(range(1, 65536))
        timeout = 0.35  # Shorter timeout for full scans
    else:
        print("Invalid choice.")
        return

    # Ask whether to export results to CSV
    do_csv = input("Export results to CSV? (y/N): ").strip().lower() == 'y'
    csv_name = None
    if do_csv:
        csv_name = input("Enter CSV filename (e.g. results.csv): ").strip() or "scan_results.csv"

    # Start scanning process
    info(f"Starting scan: {len(ips)} target(s) × {len(ports)} port(s) = {len(ips)*len(ports)} tasks")
    start = time.time()

    results_list = []   # All scan results (open + closed)
    open_records = []   # Only open ports
    seen = set()        # track (ip,port) tuples to avoid duplicates


    # Select reasonable number of threads
    total_tasks = len(ips) * len(ports)
    max_workers = 400 if total_tasks >= 1000 else 200

    # Perform concurrent scanning
    for ip, port, is_open in scan_ip_range(ips, ports, timeout=timeout, max_workers=max_workers):
        svc = try_get_service(port)
        status = "open" if is_open else "closed"
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            rec = {'ip': ip, 'port': port, 'status': status, 'service': svc}
            results_list.append(rec)
            if is_open:
                open_records.append(rec)
                success(f"{ip}:{port} open" + (f" ({svc})" if svc else ""))
            elif len(ips) == 1 and len(ports) <= 10:
                fail(f"{ip}:{port} closed")
# else: duplicate, skip

    elapsed = time.time() - start

    # Display summary of results
    title("Scan summary")
    if open_records:
        info(f"Found {len(open_records)} open services:")
        for r in sorted(open_records, key=lambda x: (x['ip'], x['port'])):
            svc_txt = f" ({r['service']})" if r['service'] else ""
            success(f"{r['ip']}:{r['port']}{svc_txt}")
    else:
        info("No open TCP ports found.")
    info(f"Elapsed: {elapsed:.2f} seconds")

    # Save to CSV if selected
    if do_csv:
        try:
            # produce a sorted copy: open ports first, then IP, then port
            sorted_rows = sorted(results_list, key=lambda r: (0 if r['status']=='open' else 1, r['ip'], int(r['port'])))
            export_to_csv(sorted_rows, csv_name)
        except Exception as e:
            print(f"Failed to write CSV: {e}")


# ---------- Program entry point ----------
if __name__ == "__main__":
    main()
