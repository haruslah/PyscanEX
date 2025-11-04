#!/usr/bin/env python3
"""
Interactive TCP port scanner with:
 - 4 scan types (default 80 / common / custom / all)
 - Option to scan a single host or a /24 network
 - CSV export prompt
"""

import socket
import time
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------- UI helpers (ANSI colors) ----------
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def title(text):
    print(f"{BOLD}{CYAN}=== {text} ==={RESET}")

def info(text):
    print(f"{YELLOW}[i]{RESET} {text}")

def success(text):
    print(f"{GREEN}[open]{RESET} {text}")

def fail(text):
    print(f"{RED}[closed]{RESET} {text}")

# ---------- Port parsing ----------
def parse_ports(spec: str):
    """Parse strings like '22,80,8000-8005' into a sorted list of unique ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a = int(a); b = int(b)
            except ValueError:
                raise ValueError(f"Invalid range: {part}")
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"Invalid range boundaries: {part}")
            ports.update(range(a, b+1))
        else:
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
    """Return True if port is open (TCP connect), False otherwise."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        sock.close()
        return True
    except Exception:
        return False

def try_get_service(port: int):
    try:
        return socket.getservbyport(port)
    except Exception:
        return ""

# ---------- Multi-target scanning ----------
def scan_targets(ips, ports, timeout=0.8, max_workers=200, show_progress=True):
    """
    Scan a list of IPs against a list of ports.
    Yields tuples (ip, port, is_open).
    """
    total = len(ips) * len(ports)
    if total == 0:
        return

    workers = min(max_workers, max(4, total))
    info(f"Using up to {workers} worker threads for {total} tasks")
    scanned = 0
    last_percent = -1

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for ip in ips:
            for p in ports:
                fut = ex.submit(scan_port_once, ip, p, timeout)
                futures[fut] = (ip, p)
        for fut in as_completed(futures):
            ip, p = futures[fut]
            try:
                is_open = fut.result()
            except Exception:
                is_open = False
            scanned += 1
            if show_progress and total > 20:
                percent = int(scanned / total * 100)
                if percent != last_percent and percent % 5 == 0:
                    info(f"Progress: {percent}% ({scanned}/{total})")
                    last_percent = percent
            yield ip, p, is_open

# ---------- Helpers for targets ----------
def expand_cidr24(spec: str):
    """
    Accept forms:
      - '192.168.1.0/24'
      - '192.168.1.' or '192.168.1'
    Returns list of IPs .1 - .254
    """
    spec = spec.strip()
    if spec.endswith('/24'):
        base = spec.split('/')[0]
    else:
        base = spec.rstrip('.')
    # if user passed full IP like 192.168.1.5, extract first 3 octets
    parts = base.split('.')
    if len(parts) == 4:
        base = '.'.join(parts[:3])
    elif len(parts) == 3:
        base = '.'.join(parts)
    else:
        raise ValueError("Invalid network prefix. Use e.g. 192.168.1.0/24 or 192.168.1.")
    ips = [f"{base}.{i}" for i in range(1, 255)]
    return ips

# ---------- Common ports ----------
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,111,123,137,138,139,143,161,162,
    179,389,443,445,465,514,520,587,631,993,995,1433,1521,1723,3306,3389,5900,8080
]

# ---------- CSV export ----------
def export_to_csv(rows, filename):
    """
    rows: iterable of dicts with keys: ip, port, status, service
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['ip','port','status','service'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    info(f"Saved results to {filename}")

# ---------- Main interactive flow ----------
def main():
    title("Simple TCP Port Scanner (host or /24)")

    mode = input("Scan mode - single host or /24 network? (host/net) [host]: ").strip().lower() or "host"
    if mode not in ('host','net'):
        print("Invalid mode. Use 'host' or 'net'. Exiting.")
        return

    target = input("Target (hostname/IP or network prefix): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return

    # Resolve single host if needed
    ips = []
    if mode == 'host':
        try:
            target_ip = socket.gethostbyname(target)
        except Exception as e:
            print(f"Could not resolve {target}: {e}")
            return
        ips = [target_ip]
        info(f"Resolved {target} -> {target_ip}")
    else:
        # mode == 'net'
        try:
            ips = expand_cidr24(target)
        except Exception as e:
            print(f"Bad network prefix: {e}")
            return
        info(f"Expanded network -> {len(ips)} hosts (1-254)")

    print()
    print("Choose scan type:")
    print("  1) Default: TCP port 80")
    print("  2) Common ports (typical services)")
    print("  3) Custom ports (e.g. 22,80,8000-8010)")
    print("  4) All ports (1-65535) -- heavy!")
    choice = input("Your choice [1-4]: ").strip()

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
        timeout = 1.0
    elif choice == "4":
        confirm = input(f"{RED}Scan all 65535 TCP ports on each host? This is very heavy. Proceed? (y/N): {RESET}").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
        ports = list(range(1, 65536))
        timeout = 0.35
    else:
        print("Invalid choice.")
        return

    # CSV export prompt
    do_csv = input("Export results to CSV? (y/N): ").strip().lower() == 'y'
    csv_name = None
    if do_csv:
        csv_name = input("Enter CSV filename (e.g. results.csv): ").strip() or "scan_results.csv"

    info(f"Starting scan: {len(ips)} target(s) × {len(ports)} port(s) = {len(ips)*len(ports)} tasks")
    start = time.time()

    results_list = []  # for CSV or post-summary
    open_records = []

    # limit max_workers to reasonable number depending on task count
    total_tasks = len(ips) * len(ports)
    max_workers = 400 if total_tasks >= 1000 else 200
    for ip, port, is_open in scan_targets(ips, ports, timeout=timeout, max_workers=max_workers):
        svc = try_get_service(port)
        status = "open" if is_open else "closed"
        # Record result
        rec = {'ip': ip, 'port': port, 'status': status, 'service': svc}
        results_list.append(rec)
        if is_open:
            open_records.append(rec)
            success(f"{ip}:{port} open" + (f" ({svc})" if svc else ""))
        # Optionally print closed ports for single-host small scans
        elif len(ips) == 1 and len(ports) <= 10:
            fail(f"{ip}:{port} closed")

    end = time.time()
    elapsed = end - start

    # Summary
    title("Scan summary")
    if open_records:
        info(f"Found {len(open_records)} open services:")
        for r in sorted(open_records, key=lambda x: (x['ip'], x['port'])):
            svc_txt = f" ({r['service']})" if r['service'] else ""
            success(f"{r['ip']}:{r['port']}{svc_txt}")
    else:
        info("No open TCP ports found.")

    info(f"Elapsed: {elapsed:.2f} seconds")

    if do_csv:
        try:
            export_to_csv(results_list, csv_name)
        except Exception as e:
            print(f"Failed to write CSV: {e}")

if __name__ == "__main__":
    main()
