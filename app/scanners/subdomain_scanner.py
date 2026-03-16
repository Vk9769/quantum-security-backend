import requests
import dns.resolver
import logging
import os
import re
import socket
import ipaddress

from app.scanners.asn_scanner import get_asn, get_asn_prefixes
from app.scanners.reverse_dns_scanner import reverse_dns

logger = logging.getLogger("SubdomainScanner")


# -----------------------------
# Check if target is IP
# -----------------------------
def is_ip(target):

    try:
        ipaddress.ip_address(target)
        return True
    except:
        return False


# -----------------------------
# crt.sh enumeration
# -----------------------------
def crtsh_enum(domain):

    logger.info("Starting crt.sh enumeration")

    url = f"https://crt.sh/?q=%25.{domain}&output=json&deduplicate=Y"

    try:

        headers = {"User-Agent": "Mozilla/5.0"}

        response = requests.get(url, headers=headers, timeout=60)

        if response.status_code != 200:
            return []

        data = response.json()

        subdomains = set()

        for entry in data:

            name = entry.get("name_value", "")

            for sub in name.split("\n"):

                sub = sub.strip()

                if domain in sub and "*" not in sub:
                    subdomains.add(sub)

        return list(subdomains)

    except Exception as e:

        logger.warning(f"crt.sh failed → {e}")
        return []


# -----------------------------
# RapidDNS enumeration
# -----------------------------
def rapiddns_enum(domain):

    logger.info("Starting RapidDNS enumeration")

    url = f"https://rapiddns.io/subdomain/{domain}?full=1"

    try:

        headers = {"User-Agent": "Mozilla/5.0"}

        r = requests.get(url, headers=headers, timeout=30)

        pattern = rf"[a-zA-Z0-9.-]+\.{re.escape(domain)}"

        matches = re.findall(pattern, r.text)

        return list(set(matches))

    except Exception as e:

        logger.warning(f"RapidDNS failed → {e}")
        return []


# -----------------------------
# VirusTotal enumeration
# -----------------------------
def virustotal_enum(domain):

    logger.info("Starting VirusTotal enumeration")

    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        logger.info("VirusTotal API key not set")
        return []

    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

    headers = {"x-apikey": api_key}

    try:

        r = requests.get(url, headers=headers, timeout=30)

        data = r.json()

        subs = []

        for item in data.get("data", []):
            subs.append(item["id"])

        return subs

    except Exception as e:

        logger.warning(f"VirusTotal failed → {e}")
        return []


# -----------------------------
# DNS brute force
# -----------------------------
def dns_bruteforce(domain):

    logger.info("Starting DNS brute force")

    wordlist = [
        "api","dev","stage","test","mail","vpn","portal","admin",
        "dashboard","app","auth","gateway","cdn","assets","blog",
        "beta","mobile","shop","support","secure","cloud",
        "login","user","account","data","db","internal"
    ]

    discovered = []

    resolver = dns.resolver.Resolver()

    resolver.timeout = 3
    resolver.lifetime = 3

    # fallback DNS servers
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    for sub in wordlist:

        hostname = f"{sub}.{domain}"

        try:

            resolver.resolve(hostname, "A")

            discovered.append(hostname)

        except:
            pass

    return discovered


# -----------------------------
# Master discovery function
# -----------------------------
def discover_subdomains(target):

    found = set()

    # If target is IP skip subdomain discovery
    if is_ip(target):

        logger.info("Target is IP → skipping subdomain enumeration")

        return [target]

    sources = [
        crtsh_enum,
        rapiddns_enum,
        virustotal_enum,
        dns_bruteforce
    ]

    for source in sources:

        try:

            results = source(target)

            for sub in results:

                sub = sub.replace("*.", "")
                found.add(sub.lower())

        except Exception as e:

            logger.warning(f"{source.__name__} failed → {e}")

    # ---------------------------------
    # ASN Infrastructure Discovery
    # ---------------------------------

    try:

        asns = get_asn(target)

        logger.info(f"Discovered ASNs → {asns}")

        for asn in asns:

            prefixes = get_asn_prefixes(asn)

            for prefix in prefixes[:3]:

                hosts = reverse_dns(prefix)

                for h in hosts:

                    if target in h:
                        found.add(h.lower())

    except Exception as e:

        logger.warning(f"ASN discovery failed → {e}")

    return sorted(found)