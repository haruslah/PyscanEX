# PyscanEx

---

## Overview

**PyscanEx** is a small interactive TCP port scanner written in Python. It supports:

- Scanning a **single host** or an **IPv4 network** (CIDR; commonly `/24`, but other prefixes are accepted)
- Four scan types:
  - **Default** (port 80)
  - **Common ports** (typical service ports)
  - **Custom lists / ranges**
  - **All ports** (1–65535) — with explicit warning
- Optional CSV export of results (`ip,port,status,service`)

The scanner uses `socket.connect_ex()` to test TCP ports; a return code of `0` indicates an open port.

---

## Requirements

- Python **3.7+** (3.9+ recommended)
- Standard library only:
  - `socket`, `time`, `csv`, `ipaddress`, `concurrent.futures`

No third-party packages required.

---

## How it works (high level)

1. User chooses mode: `host` (single hostname/IP) or `net` (CIDR/network prefix).
2. Script resolves the hostname (if `host`) or expands the prefix into usable hosts (CIDR — e.g., `.1`–`.254` for `/24`).
3. User chooses scan type (1–4). The script builds a list of ports to test.
4. `scan_ip_range()` runs `scan_port_once()` which calls `socket.connect_ex((ip, port))` with a small timeout.
5. `scan_ip_range()` yields results as tasks complete. Open ports are highlighted and collected; optionally results are saved to CSV.

---

## Run / Usage

Run the script from the project directory:

```bash
# make it executable and run
chmod +x pyscanex.py
./pyscanex.py

# or use python
python3 pyscanex.py
