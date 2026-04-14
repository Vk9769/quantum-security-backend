import requests
import dns.resolver
import socket
import json
import subprocess
import sys
import threading
import shutil
import os
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# CONFIG
# -----------------------------
MAX_THREADS = 50
OUTPUT_FILE = "scan_output.json"
TXT_OUTPUT = "scan_output.txt"
AMASS_FILE = "amass.txt"
TEMP_FILE = "scan_progress.json"
AMASS_JSON = "amass_progress.json"

# -----------------------------
# GLOBAL STATE
# -----------------------------
results = []
scanned_domains = set()
amass_subs = set()
lock = threading.Lock()

# -----------------------------
# DNS RESOLVER
# -----------------------------
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 2
resolver.lifetime = 2

# -----------------------------
# LOAD SCAN PROGRESS
# -----------------------------
def load_progress():
    global results, scanned_domains

    if os.path.exists(TEMP_FILE):
        print("♻️ Resuming scan progress...\n")
        try:
            with open(TEMP_FILE, "r", encoding="utf-8") as f:
                results = json.load(f)
        except:
            results = []

        scanned_domains = set([r["domain"] for r in results])
        print(f"✅ Loaded {len(scanned_domains)} scanned entries\n")

# -----------------------------
# LOAD AMASS JSON (FIXED)
# -----------------------------
def load_amass_json():
    global amass_subs

    if os.path.exists(AMASS_JSON):
        print("♻️ Resuming Amass JSON...\n")
        try:
            with open(AMASS_JSON, "r", encoding="utf-8") as f:
                data = f.read().strip()
                if data:
                    amass_subs = set(json.loads(data))
                else:
                    amass_subs = set()
        except:
            amass_subs = set()

        print(f"✅ Loaded {len(amass_subs)} subdomains\n")

# -----------------------------
# SAVE AMASS JSON
# -----------------------------
def save_amass_json():
    with open(AMASS_JSON, "w", encoding="utf-8") as f:
        json.dump(list(amass_subs), f, indent=2)

    print(f"💾 Amass JSON saved ({len(amass_subs)})")

# -----------------------------
# AUTO SAVE SCAN
# -----------------------------
def auto_save():
    with lock:
        with open(TEMP_FILE, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print(f"💾 Scan auto-saved ({len(results)} results)")

# -----------------------------
# CTRL + C HANDLER
# -----------------------------
def handle_exit(signal_received, frame):
    print("\n⚠️ Interrupted! Saving everything...")

    auto_save()
    save_amass_json()

    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# -----------------------------
# CHECK DOCKER
# -----------------------------
def check_docker():
    if not shutil.which("docker"):
        print("❌ Docker not installed")
        sys.exit(1)

# -----------------------------
# RUN AMASS (🔥 FIXED EXTRACTION)
# -----------------------------
def run_amass(domain):
    print(f"\n🚀 Running Amass for {domain}...\n")

    subs = set()

    load_amass_json()
    subs.update(amass_subs)

    if os.path.exists(AMASS_FILE):
        print("♻️ Loading existing subdomains from amass.txt...\n")
        with open(AMASS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                sub = line.strip()
                if sub:
                    subs.add(sub)

    cmd = [
        "docker", "run", "--rm",
        "caffix/amass",
        "enum",
        "-passive",
        "-norecursive",
        "-d", domain
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    try:
        for line in process.stdout:
            line = line.strip()
            print(f"[AMASS] {line}")

            # 🔥 FIX: extract ANY valid subdomain
            parts = line.split()

            for part in parts:
                if part.endswith(domain) and " " not in part:
                    sub = part.strip()

                    if sub not in subs:
                        subs.add(sub)
                        amass_subs.add(sub)

                        with open(AMASS_FILE, "a", encoding="utf-8") as f:
                            f.write(sub + "\n")

                        save_amass_json()
                        print(f"💾 Saved: {sub}")

    except KeyboardInterrupt:
        print("\n⚠️ Amass interrupted!")
        process.kill()

    process.wait()

    print(f"\n✅ Total subdomains: {len(subs)}\n")
    return list(subs)

# -----------------------------
# DNS RECORDS
# -----------------------------
def get_dns_records(domain):
    data = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "CNAME": [],
        "TXT": []
    }

    for rtype in data.keys():
        try:
            answers = resolver.resolve(domain, rtype)
            for r in answers:
                data[rtype].append(str(r))
        except:
            pass

    return data

# -----------------------------
# PTR
# -----------------------------
def get_ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# -----------------------------
# IP INFO
# -----------------------------
def get_ip_info(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        return r.json()
    except:
        return {}

# -----------------------------
# SCAN DOMAIN
# -----------------------------
def scan_domain(domain):
    print(f"[SCAN] {domain}")

    dns_data = get_dns_records(domain)
    ips = dns_data["A"] + dns_data["AAAA"]

    entries = []

    if not ips:
        entry = {
            "domain": f"{domain} -> NO_IP",
            **dns_data,
            "PTR": [],
            "IP_INFO": []
        }
        entries.append(entry)

    for ip in ips:
        entry = {
            "domain": f"{domain} -> {ip}",
            **dns_data,
            "PTR": [],
            "IP_INFO": []
        }

        ptr = get_ptr(ip)
        if ptr:
            entry["PTR"].append(ptr)

        info = get_ip_info(ip)
        if info:
            entry["IP_INFO"].append(info)

        entries.append(entry)

    with lock:
        for e in entries:
            if e["domain"] not in scanned_domains:
                results.append(e)
                scanned_domains.add(e["domain"])

    auto_save()

# -----------------------------
# MASS SCAN
# -----------------------------
def mass_scan(domains):
    total = len(domains)
    done = 0

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_domain, d): d for d in domains}

        for future in as_completed(futures):
            done += 1
            domain = futures[future]

            try:
                future.result()
            except Exception as e:
                print(f"❌ Error: {domain} → {e}")

            print(f"[PROGRESS] {done}/{total}")

# -----------------------------
# FINAL SAVE
# -----------------------------
def save_output():
    print("\n💾 Final Saving...\n")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print("✅ Final files saved!")

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python mass_scanner.py domain.com")
        sys.exit(1)

    check_docker()

    domain = sys.argv[1]

    load_progress()

    subdomains = run_amass(domain)

    print(f"DEBUG: Found {len(subdomains)} subdomains")

    if not subdomains:  
        print("❌ No subdomains found")
        sys.exit(1)

    print(f"\n🔥 Scanning {len(subdomains)} domains...\n")

    mass_scan(subdomains)

    save_output()

    print("\n🎯 DONE!")