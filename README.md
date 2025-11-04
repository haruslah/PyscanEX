# PyscanEX — Documentation

---

## Overview

PyscanEX is a small interactive TCP port scanner. It supports:

* Scanning a **single host** or a **/24 network** (.1–.254)
* Four scan types: **default (port 80)**, **common ports**, **custom port lists/ranges**, and **all ports (1–65535)**
* Concurrent scanning using a thread pool for speed
* Optional CSV export of results

The scanner uses `socket.connect_ex()` to test TCP ports; a return code of `0` indicates an open port.

---

## Requirements

* Python 3.7+ (recommended)
* Standard library only: `socket`, `time`, `csv`, `concurrent.futures`

No third‑party packages required.

---

## How it works (high level)

1. User chooses mode: `host` (single hostname/IP) or `net` (network prefix that expands to a /24).
2. Script resolves the hostname (if `host`) or expands the prefix to `.1`–`.254` (if `net`).
3. User chooses scan type (1–4). The script builds a list of ports to test.
4. The scanner submits tasks to a `ThreadPoolExecutor` where each task runs `scan_port_once()` which calls `socket.connect_ex((ip, port))` with a small timeout.
5. Results are yielded from `scan_targets()` and printed. Open ports are highlighted and collected. Optionally results are saved to CSV.

---

## Run / Usage

Run the script directly:

```bash
./scanner.py
# or
python3 scanner.py
```

When prompted:

* `Scan mode - single host or /24 network? (host/net) [host]:`  — choose `host` or `net`
* `Target (hostname/IP or network prefix):` — examples:

  * `example.com` (single host)
  * `192.168.1.0/24` or `192.168.1.` or `192.168.1` (network)
* Choose scan type 1–4. For custom ports, enter e.g. `22,80,8000-8010`.
* Optionally export to CSV and provide filename.

Example interactive session (abbreviated):

```
Scan mode - single host or /24 network? (host/net) [host]: host
Target (hostname/IP or network prefix): example.com
Your choice [1-4]: 2
Export results to CSV? (y/N): y
Enter CSV filename (e.g. results.csv): myscan.csv
```

---

## Important functions and details

### `parse_ports(spec: str)`

* Accepts a comma-separated list of ports and ranges, e.g. `22,80,8000-8005`.
* Validates boundaries (1–65535) and range `a-b` where `a <= b`.
* Returns a **sorted list of unique** port integers.
* Raises `ValueError` on malformed input.

### `scan_port_once(target_ip: str, port: int, timeout: float = 0.8) -> bool`

* Creates a TCP socket and calls `socket.connect_ex((target_ip, port))`.
* Returns `True` if `connect_ex()` returns `0` (success / open), otherwise `False`.
* Uses a socket timeout to avoid blocking for too long.
* Ensures socket is closed in a `finally` block.

### `try_get_service(port: int)`

* Uses `socket.getservbyport()` to map a port to its well-known service name where available.
* Returns an empty string on failure.

### `expand_cidr24(spec: str)`

* Accepts forms like `192.168.1.0/24`, `192.168.1.`, `192.168.1` or even a full IP `192.168.1.5`.
* Normalizes to the first three octets and returns `.1` through `.254` as a list of IP strings.
* Raises `ValueError` for invalid prefixes.

### `scan_targets(ips, ports, timeout=0.8, max_workers=200, show_progress=True)`

* Orchestrates concurrent scanning across many IPs and ports.
* Uses `ThreadPoolExecutor` and yields `(ip, port, is_open)` tuples as tasks complete.
* Prints progress updates for large scans.
* `max_workers` is capped relative to task count for safety.

### `export_to_csv(rows, filename)`

* Writes an iterable of dictionaries with keys `ip`, `port`, `status`, `service` to a CSV file with those headers.

---

## Performance & tuning

* **Timeout**: Lower timeouts speed up scanning but increase false negatives on slow networks. Defaults in the script: `0.8s` for small scans, `0.35s` for full 1–65535 scans.
* **Workers**: The script chooses `workers = min(max_workers, max(4, total_tasks))`. You can adjust `max_workers` in the main flow. Beware of using extremely high thread counts — your machine or the network may suffer.
* **Large scans**: Scanning all 65535 ports on many hosts is heavy. Reduce the port range or scan subsets if you hit system limits.

---

## Output format

* Console: open ports are printed with an `[open]` tag; closed ports may be shown for small single-host scans.
* CSV: columns `ip,port,status,service` where `status` is `open` or `closed` and `service` may be empty.

Sample CSV row:

```
ip,port,status,service
192.168.1.10,22,open,ssh
```

---

## Limitations

* IPv4-only.
* Basic service identification (relies on `getservbyport()` which maps well-known ports only).
* No built-in parallelism control by CPU affinity or process pools; uses threads only.

