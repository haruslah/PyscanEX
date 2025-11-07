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
# Simple functions to print colored/marked output to terminal so results are easier to read.
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"

def title(text):
    """Print a bold cyan section title."""
    print(f"{BOLD}{CYAN}=== {text} ==={RESET}")

def info(text):
    """Print informational message in yellow."""
    print(f"{YELLOW}[i]{RESET} {text}")

def success(text):
    """Print positive/open result in green."""
    print(f"{GREEN}[open]{RESET} {text}")

def fail(text):
    """Print negative/closed result in red."""
    print(f"{RED}[closed]{RESET} {text}")

# ---------- Port parsing ----------
def parse_ports(spec: str):
    """
    Convert a user string like "22,80,8000-8005" to a sorted list of unique ints.

    - Accepts comma-separated numbers and ranges (x-y).
    - Validates port boundaries (1..65535).
    - Returns a sorted list (ascending).
    Raises ValueError on bad input.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        # range form "a-b"
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a = int(a); b = int(b)
            except ValueError:
                raise ValueError(f"Invalid range: {part}")
            # basic validation: ports in range and a <= b
            if a < 1 or b > 65535 or a > b:
                raise ValueError(f"Invalid range boundaries: {part}")
            # add inclusive range
            ports.update(range(a, b+1))
        else:
            # single port
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
    """
    Attempt a TCP connect to (target_ip, port).
    - Uses socket.connect_ex which returns 0 on success (open).
    - Returns True if port is open, False otherwise.
    - Uses timeout to avoid long blocking waits.
    - Ensures socket is closed in finally block.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Small timeout keeps scan fast; lowering it risks false negatives on slow networks.
        sock.settimeout(timeout)
        # connect_ex returns 0 on success, errno-like value on failure
        rc = sock.connect_ex((target_ip, port))
        return rc == 0
    except Exception:
        # Any exception (rare) is treated as "closed" to keep scanner robust.
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass  # best-effort close

def try_get_service(port: int):
    """
    Map a port number to the common service name (if known), e.g. 80 -> 'http'.
    Falls back to empty string on failure (unknown or permission error).
    """
    try:
        return socket.getservbyport(port)
    except Exception:
        return ""

# ---------- Multi-target scanning ----------
def scan_ip_range(ips, ports, timeout=0.8, max_workers=200, show_progress=True):
    """
    Concurrently scan every (ip, port) pair.

    Inputs:
      - ips: iterable/list of IP strings
      - ports: iterable/list of port ints
      - timeout: per-socket timeout (seconds)
      - max_workers: maximum concurrent threads (ThreadPoolExecutor)
      - show_progress: whether to print occasional progress updates

    Yields:
      (ip, port, is_open) tuples as results become available.

    Notes:
      - Uses ThreadPoolExecutor since socket I/O is blocking and benefits from threads.
      - Limits workers to <= total tasks (and to a minimum of 4).
      - Prints progress every 5% when total tasks > 20 to avoid noisy output.
    """
    total = len(ips) * len(ports)
    if total == 0:
        return

    # choose worker count sensibly to avoid overwhelming machine or network
    workers = min(max_workers, max(4, total))
    info(f"Using up to {workers} worker threads for {total} tasks")
    scanned = 0
    last_percent = -1

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        # submit all tasks: each task is scan_port_once(ip, port)
        for ip in ips:
            for p in ports:
                fut = ex.submit(scan_port_once, ip, p, timeout)
                futures[fut] = (ip, p)
        # as_completed yields futures as they finish (not in submission order)
        for fut in as_completed(futures):
            ip, p = futures[fut]
            try:
                is_open = fut.result()
            except Exception:
                # Defensive: if a worker throws, consider that port closed
                is_open = False
            scanned += 1
            # optional progress update (coarse)
            if show_progress and total > 20:
                percent = int(scanned / total * 100)
                if percent != last_percent and percent % 5 == 0:
                    info(f"Progress: {percent}% ({scanned}/{total})")
                    last_percent = percent
            yield ip, p, is_open

# ---------- Helpers for targets ----------
def expand_cidr24(spec: str):
    """
    Accept user input as:
      - '192.168.1.0/24'
      - '192.168.1.' or '192.168.1'
      - '192.168.1.5' (full IP) -> will use the first three octets

    Returns list of IP strings from .1 to .254 (typical host range in /24).
    Raises ValueError on malformed input.
    """
    spec = spec.strip()
    if spec.endswith('/24'):
        base = spec.split('/')[0]
    else:
        base = spec.rstrip('.')
    # If user gave a full IP, keep only the first 3 octets
    parts = base.split('.')
    if len(parts) == 4:
        base = '.'.join(parts[:3])
    elif len(parts) == 3:
        base = '.'.join(parts)
    else:
        # invalid prefix like "192.168" or "10"
        raise ValueError("Invalid network prefix. Use e.g. 192.168.1.0/24 or 192.168.1.")
    # Return hosts .1 through .254 (skip .0 and .255)
    ips = [f"{base}.{i}" for i in range(1, 255)]
    return ips

# ---------- Common ports ----------
# Handy set of commonly used TCP ports to scan in "common" mode.
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,111,123,137,138,139,143,161,162,
    179,389,443,445,465,514,520,587,631,993,995,1433,1521,1723,3306,3389,5900,8080
]

# ---------- CSV export ----------
def export_to_csv(rows, filename):
    """
    rows: iterable of dicts with keys: ip, port, status, service
    Writes a standard CSV with header: ip,port,status,service.
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['ip','port','status','service'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    info(f"Saved results to {filename}")

# ---------- Main interactive flow ----------
def main():
    # Title and initial prompts
    title("Simple TCP Port Scanner (host or /24)")

    # Ask whether user wants to scan a single host or an entire /24 network
    mode = input("Scan mode - single host or /24 network? (host/net) [host]: ").strip().lower() or "host"
    if mode not in ('host','net'):
        print("Invalid mode. Use 'host' or 'net'. Exiting.")
        return

    # Get target string (hostname, IP, or network prefix)
    target = input("Target (hostname/IP or network prefix): ").strip()
    if not target:
        print("No target provided. Exiting.")
        return

    # Resolve single host to IP, or expand prefix into list of IPs
    ips = []
    if mode == 'host':
        try:
            # resolve DNS name to IP; this also accepts IP addresses directly
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

    # Choose scan type (affects port list and timeouts)
    print()
    print("Choose scan type:")
    print("  1) Default: TCP port 80")
    print("  2) Common ports (typical services)")
    print("  3) Custom ports (e.g. 22,80,8000-8010)")
    print("  4) All ports (1-65535)")
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
        # custom scans might include slower targets -> increase timeout slightly
        timeout = 1.0
    elif choice == "4":
        # warn user: scanning all ports is resource- and time-intensive
        confirm = input(f"{RED}Scan all 65535 TCP ports on each host? This is very heavy. {YELLOW}Proceed? (y/N): {RESET}").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
        ports = list(range(1, 65536))
        # reduce timeout for large scans to keep reasonable total time (trade-off: more false negatives)
        timeout = 0.35
    else:
        print("Invalid choice.")
        return

    # Ask whether to save results to CSV for later review
    do_csv = input("Export results to CSV? (y/N): ").strip().lower() == 'y'
    csv_name = None
    if do_csv:
        csv_name = input("Enter CSV filename (e.g. results.csv): ").strip() or "scan_results.csv"

    info(f"Starting scan: {len(ips)} target(s) × {len(ports)} port(s) = {len(ips)*len(ports)} tasks")
    start = time.time()

    # Store results for CSV or summary
    results_list = []
    open_records = []

    # choose a reasonable thread pool size based on task count
    total_tasks = len(ips) * len(ports)
    max_workers = 400 if total_tasks >= 1000 else 200

    # Perform scanning (scan_ip_range yields results as they complete)
    for ip, port, is_open in scan_ip_range(ips, ports, timeout=timeout, max_workers=max_workers):
        svc = try_get_service(port)           # try mapping port to service name
        status = "open" if is_open else "closed"
        # record the result (dict keys match CSV header)
        rec = {'ip': ip, 'port': port, 'status': status, 'service': svc}
        results_list.append(rec)
        if is_open:
            open_records.append(rec)
            # print open services as they are discovered
            success(f"{ip}:{port} open" + (f" ({svc})" if svc else ""))
        # For small single-host scans, also print closed ports so student can see negatives
        elif len(ips) == 1 and len(ports) <= 10:
            fail(f"{ip}:{port} closed")

    end = time.time()
    elapsed = end - start

    # Summary section: show discovered open services (sorted for readability)
    title("Scan summary")
    if open_records:
        info(f"Found {len(open_records)} open services:")
        for r in sorted(open_records, key=lambda x: (x['ip'], x['port'])):
            svc_txt = f" ({r['service']})" if r['service'] else ""
            success(f"{r['ip']}:{r['port']}{svc_txt}")
    else:
        info("No open TCP ports found.")

    info(f"Elapsed: {elapsed:.2f} seconds")

    # If CSV selected, write results
    if do_csv:
        try:
            export_to_csv(results_list, csv_name)
        except Exception as e:
            print(f"Failed to write CSV: {e}")

if __name__ == "__main__":
    main()
