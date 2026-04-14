import requests
import dns.resolver
import logging
import os
import re
import socket
import ipaddress
import sys

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SubdomainScanner")

print("VT KEY:", os.getenv("VT_API_KEY"))


# -----------------------------
# Check if target is IP
# -----------------------------
def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except:
        return False


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return None


# -----------------------------
# crt.sh enumeration (FIXED)
# -----------------------------
def crtsh_enum(domain):
    logger.info("crt.sh enumeration")

    urls = [
        f"https://crt.sh/?q=%25.{domain}&output=json",
        f"https://crt.sh/?q=%.{domain}&output=json"
    ]

    subs = set()
    headers = {"User-Agent": "Mozilla/5.0"}

    for url in urls:
        try:
            r = requests.get(url, headers=headers, timeout=60)

            if r.status_code != 200:
                continue

            try:
                data = r.json()
            except:
                logger.warning("crt.sh returned invalid JSON")
                continue

            for entry in data:
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip()
                    if sub.endswith(domain) and "*" not in sub:
                        subs.add(sub)

        except Exception as e:
            logger.warning(f"crt.sh failed → {e}")

    return list(subs)


# -----------------------------
# RapidDNS
# -----------------------------
def rapiddns_enum(domain):
    logger.info("RapidDNS enumeration")

    url = f"https://rapiddns.io/subdomain/{domain}?full=1"

    try:
        r = requests.get(url, timeout=30)
        pattern = rf"[a-zA-Z0-9.-]+\.{re.escape(domain)}"
        return list(set(re.findall(pattern, r.text)))

    except Exception as e:
        logger.warning(f"RapidDNS failed → {e}")
        return []


# -----------------------------
# VirusTotal (FULL pagination)
# -----------------------------
def virustotal_enum(domain):
    logger.info("VirusTotal enumeration")

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        logger.warning("No VT API key")
        return []

    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    subs = set()

    try:
        while url:
            r = requests.get(url, headers=headers, timeout=30)
            data = r.json()

            for item in data.get("data", []):
                subs.add(item["id"])

            url = data.get("links", {}).get("next")

        return list(subs)

    except Exception as e:
        logger.warning(f"VT failed → {e}")
        return []


# -----------------------------
# Small brute
# -----------------------------
def dns_bruteforce(domain):
    logger.info("Basic brute force")

    wordlist = [
        "api","dev","stage","test","mail","vpn","portal","admin",
        "dashboard","app","auth","gateway","cdn","assets","blog",
        "beta","mobile","shop","support","secure","cloud",
        "login","user","account","data","db","internal"
    ]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    found = []

    for word in wordlist:
        sub = f"{word}.{domain}"
        try:
            resolver.resolve(sub, "A")
            found.append(sub)
        except:
            pass

    return found


# -----------------------------
# Pattern brute
# -----------------------------
def pattern_bruteforce(domain):
    logger.info("Pattern brute force (pnbXXXX)")

    return [f"pnb{i}.{domain}" for i in range(1, 3000)]


# -----------------------------
# Resolve alive + dead
# -----------------------------
def resolve_all(subdomains):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 2
    resolver.lifetime = 2

    alive = []
    dead = []

    def check(sub):
        try:
            answers = resolver.resolve(sub, "A")
            return ("alive", sub, answers[0].to_text())
        except:
            return ("dead", sub, None)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check, sub) for sub in subdomains]

        count = 0
        for future in as_completed(futures):
            count += 1
            if count % 200 == 0:
                print(f"[+] Checked {count} domains...")

            status, sub, ip = future.result()

            if status == "alive":
                alive.append((sub, ip))
            else:
                dead.append(sub)

    return alive, dead


# -----------------------------
# MASTER FUNCTION
# -----------------------------
def discover_subdomains(target):
    found = set()

    if is_ip(target):
        return [(target, target)], [], []

    sources = [
        crtsh_enum,
        rapiddns_enum,
        virustotal_enum,
        dns_bruteforce,
        pattern_bruteforce
    ]

    for source in sources:
        try:
            subs = source(target)

            for sub in subs:
                sub = sub.replace("*.", "").lower().strip()

                if sub.endswith(target):
                    found.add(sub)

        except Exception as e:
            logger.warning(f"{source.__name__} failed → {e}")

    logger.info(f"Total raw found: {len(found)}")

    alive, dead = resolve_all(found)

    return found, alive, dead


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python test_scanner.py domain.com")
        sys.exit(1)

    domain = sys.argv[1]

    raw, alive, dead = discover_subdomains(domain)

    print("\n🔥 ALIVE SUBDOMAINS:\n")

    for sub, ip in alive:
        print(f"{sub} -> {ip}")   # ✅ changed arrow

    print(f"\n📊 SUMMARY:")
    print(f"RAW: {len(raw)}")
    print(f"ALIVE: {len(alive)}")
    print(f"DEAD: {len(dead)}")

    # ✅ FIXED FILE WRITING (UTF-8)
    with open("raw.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(raw))

    with open("alive.txt", "w", encoding="utf-8") as f:
        for sub, ip in alive:
            f.write(f"{sub} -> {ip}\n")

    with open("dead.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(dead))

    print("\n📁 Files saved: raw.txt, alive.txt, dead.txt")