import requests
import logging
import socket

logger = logging.getLogger("ASNScanner")

BGPVIEW_API = "https://api.bgpview.io"


# -----------------------------------
# Resolve domain to IP
# -----------------------------------

def resolve_ip(domain):

    try:

        ip = socket.gethostbyname(domain)

        logger.info(f"Resolved {domain} → {ip}")

        return ip

    except Exception as e:

        logger.warning(f"DNS resolution failed → {domain} | {e}")

        return None


# -----------------------------------
# ASN Lookup
# -----------------------------------

def get_asn(domain):

    logger.info(f"Finding ASN for domain → {domain}")

    try:

        url = f"{BGPVIEW_API}/dns/{domain}"

        r = requests.get(url, timeout=15)

        if r.status_code != 200:
            logger.warning("BGPView API returned non-200")
            return []

        data = r.json()

        asns = []

        for entry in data.get("data", {}).get("ipv4_addresses", []):
            asn = entry.get("asn")
            if asn:
                asns.append(asn)

        asns = list(set(asns))

        logger.info(f"Discovered ASNs → {asns}")

        return asns

    except Exception as e:

        logger.warning(f"ASN lookup failed → {e}")

        # fallback using resolved IP
        ip = resolve_ip(domain)

        if ip:
            logger.info(f"Fallback ASN lookup using IP → {ip}")

        return []


# -----------------------------------
# ASN Prefix Lookup
# -----------------------------------

def get_asn_prefixes(asn):

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