# Incident Response Toolkit
REPORT_DIR = "reports"   # Where to save JSON reports
LOG_PATH    = "/var/log/auth.log"  # Path to your auth log file
SCAN_PATHS  = ["."]     # Directories to scan for file hashes
SCAN_EXTS   = [".py", ".sh", ".exe", ".dll"]  # File extensions to include

---

### 🛠 ir_toolkit.py

Save the following script as `ir_toolkit.py` in the same repository root. This is a **separate** file from `README.md`.

```python
#!/usr/bin/env python3
"""
ir_toolkit.py

A standalone Incident Response toolkit using only the Python standard library.
Generates a JSON report containing system info, auth log events, and file hashes.
"""

import os
import sys
import platform
import subprocess
import hashlib
import json
from datetime import datetime
from argparse import ArgumentParser

# ——— Configurable Constants ———
REPORT_DIR = "reports"
LOG_PATH    = "/var/log/auth.log"   # adjust as needed for your OS
SCAN_PATHS  = ["."]                 # directories to scan for hashes
SCAN_EXTS   = [".py", ".sh", ".exe", ".dll"]  # file types to hash

# ——— Helpers ———
def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)

# ——— Collectors ———
def collect_system_info():
    info = {"hostname": platform.node(), "os": platform.platform()}
    try:
        info["uptime"] = subprocess.check_output(["uptime"], stderr=subprocess.DEVNULL).decode().strip()
    except:
        info["uptime"] = "N/A"
    try:
        info["cpu"] = subprocess.check_output(["lscpu"], stderr=subprocess.DEVNULL).decode().strip()
    except:
        info["cpu"] = "N/A"
    try:
        info["memory"] = subprocess.check_output(["free", "-h"], stderr=subprocess.DEVNULL).decode().strip()
    except:
        info["memory"] = "N/A"
    return info


def parse_auth_log(path=LOG_PATH, keywords=None):
    if keywords is None:
        keywords = ["Failed password", "Accepted password", "sudo"]
    events = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                if any(kw in line for kw in keywords):
                    events.append(line.strip())
    except FileNotFoundError:
        events.append(f"Log not found: {path}")
    return events


def compute_hash(file_path, algo="sha256"):
    h = hashlib.new(algo)
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None


def scan_hashes(paths=SCAN_PATHS, exts=SCAN_EXTS):
    results = {}
    for base in paths:
        for root, _, files in os.walk(base):
            for fn in files:
                if any(fn.lower().endswith(ext) for ext in exts):
                    full = os.path.join(root, fn)
                    digest = compute_hash(full)
                    if digest:
                        results[full] = digest
    return results

# ——— Reporting ———
def save_report(data, directory=REPORT_DIR):
    ensure_dir(directory)
    fname = f"{directory}/ir_report_{timestamp()}.json"
    with open(fname, "w") as f:
        json.dump(data, f, indent=2)
    return fname

# ——— Main CLI ———
def main():
    p = ArgumentParser(description="Incident Response Toolkit")
    p.add_argument("--report", action="store_true", help="Generate a report and exit")
    args = p.parse_args()

    report = {
        "timestamp":   timestamp(),
        "system_info": collect_system_info(),
        "auth_events": parse_auth_log(),
        "file_hashes": scan_hashes(),
    }

    if args.report:
        path = save_report(report)
        print(f"[+] Report written to {path}")
        sys.exit(0)

    print("\n=== System Info ===")
    for k, v in report["system_info"].items():
        print(f"{k}: {v if len(v)<80 else v[:80]+'...'}")
    print("\n=== Auth Events ===")
    for evt in report["auth_events"][-10:]:
        print(evt)
    print(f"\n[+] Scanned {len(report['file_hashes'])} files for hashes.")
    print("\nRun with `--report` to save full JSON report.\n")

if __name__ == "__main__":
    main()
