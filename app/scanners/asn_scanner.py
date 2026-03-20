import requests
import logging
import socket
import ipaddress
from typing import Optional, List, Dict, Any

logger = logging.getLogger("ASNScanner")

BGPVIEW_API = "https://api.bgpview.io"
IPINFO_API = "https://ipinfo.io"


# -----------------------------------
# Helpers
# -----------------------------------

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


# -----------------------------------
# Resolve domain to IP
# -----------------------------------

def resolve_ip(domain: str) -> Optional[str]:
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved {domain} → {ip}")
        return ip

    except Exception as e:
        logger.warning(f"DNS resolution failed → {domain} | {e}")
        return None


# -----------------------------------
# Get ASN from domain using BGPView DNS API
# -----------------------------------

def get_asn(domain: str) -> List[int]:
    logger.info(f"Finding ASN for domain → {domain}")

    try:
        url = f"{BGPVIEW_API}/dns/{domain}"
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            logger.warning(f"BGPView DNS API returned {r.status_code}")
            return []

        data = r.json()
        asns = []

        for entry in data.get("data", {}).get("ipv4_addresses", []):
            asn = entry.get("asn")
            if asn:
                try:
                    asns.append(int(asn))
                except Exception:
                    pass

        asns = list(set(asns))

        logger.info(f"Discovered ASNs → {asns}")
        return asns

    except Exception as e:
        logger.warning(f"ASN lookup failed for domain {domain} → {e}")
        return []


# -----------------------------------
# Get ASN from IP using ipinfo
# -----------------------------------

def get_asn_from_ip(ip: str) -> Optional[int]:
    logger.info(f"Finding ASN for IP → {ip}")

    try:
        url = f"{IPINFO_API}/{ip}/json"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            logger.warning(f"ipinfo API returned {r.status_code}")
            return None

        data = r.json()
        org = data.get("org", "")

        # Example: "AS13335 Cloudflare, Inc."
        if org.startswith("AS"):
            first_part = org.split()[0].replace("AS", "").strip()
            if first_part.isdigit():
                asn = int(first_part)
                logger.info(f"Resolved IP {ip} → ASN {asn}")
                return asn

    except Exception as e:
        logger.warning(f"ASN lookup failed for IP {ip} → {e}")

    return None


# -----------------------------------
# Get org name from IP using ipinfo
# -----------------------------------

def get_asn_org(ip: str) -> Optional[str]:
    logger.info(f"Finding ASN org for IP → {ip}")

    try:
        url = f"{IPINFO_API}/{ip}/json"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            logger.warning(f"ipinfo org API returned {r.status_code}")
            return None

        data = r.json()
        org = data.get("org")

        if org:
            logger.info(f"Resolved IP {ip} → Org {org}")
            return org

    except Exception as e:
        logger.warning(f"ASN org lookup failed for IP {ip} → {e}")

    return None


# -----------------------------------
# Get company/provider name from ASN
# -----------------------------------

def get_asn_details(asn: int) -> Dict[str, Any]:
    logger.info(f"Fetching ASN details for ASN {asn}")

    try:
        url = f"{BGPVIEW_API}/asn/{asn}"
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            logger.warning(f"BGPView ASN details API returned {r.status_code}")
            return {}

        data = r.json().get("data", {})

        result = {
            "asn": data.get("asn"),
            "name": data.get("name"),
            "description": data.get("description_short"),
            "country_code": data.get("country_code"),
            "rir_name": data.get("rir_name"),
        }

        logger.info(f"ASN details fetched → {result}")
        return result

    except Exception as e:
        logger.warning(f"ASN details lookup failed for ASN {asn} → {e}")
        return {}


# -----------------------------------
# ASN Prefix Lookup
# -----------------------------------

def get_asn_prefixes(asn: int) -> List[str]:
    logger.info(f"Fetching prefixes for ASN {asn}")

    try:
        url = f"{BGPVIEW_API}/asn/{asn}/prefixes"
        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            logger.warning(f"BGPView prefix API returned {r.status_code}")
            return []

        data = r.json()
        prefixes = []

        for p in data.get("data", {}).get("ipv4_prefixes", []):
            prefix = p.get("prefix")
            if prefix:
                prefixes.append(prefix)

        logger.info(f"Discovered {len(prefixes)} prefixes for ASN {asn}")
        return prefixes

    except Exception as e:
        logger.warning(f"ASN prefix lookup failed → {e}")
        return []


# -----------------------------------
# Full ASN enrichment for host/domain/IP
# -----------------------------------

def enrich_asn(target: str) -> Dict[str, Any]:
    """
    Accepts:
    - domain like example.com
    - IP like 8.8.8.8

    Returns:
    {
        "ip": "...",
        "asns": [13335],
        "primary_asn": 13335,
        "org": "AS13335 Cloudflare, Inc.",
        "asn_details": {...},
        "prefixes": [...]
    }
    """
    result = {
        "ip": None,
        "asns": [],
        "primary_asn": None,
        "org": None,
        "asn_details": {},
        "prefixes": []
    }

    try:
        ip = target if is_ip(target) else resolve_ip(target)
        result["ip"] = ip

        if not ip:
            return result

        # Domain path first
        if not is_ip(target):
            asns = get_asn(target)
        else:
            asns = []

        # Fallback IP ASN
        if not asns:
            ip_asn = get_asn_from_ip(ip)
            if ip_asn:
                asns = [ip_asn]

        asns = list(set(asns))
        result["asns"] = asns

        if asns:
            primary_asn = asns[0]
            result["primary_asn"] = primary_asn
            result["asn_details"] = get_asn_details(primary_asn)
            result["prefixes"] = get_asn_prefixes(primary_asn)

        result["org"] = get_asn_org(ip)

        return result

    except Exception as e:
        logger.warning(f"ASN enrichment failed for {target} → {e}")
        return result