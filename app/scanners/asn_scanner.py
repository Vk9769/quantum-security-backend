import requests
import logging

logger = logging.getLogger("ASNScanner")


def get_asn(domain):

    logger.info("Finding ASN for domain")

    try:

        url = f"https://api.bgpview.io/dns/{domain}"

        r = requests.get(url, timeout=20)

        data = r.json()

        asns = []

        for entry in data["data"]["ipv4_addresses"]:
            asns.append(entry["asn"])

        return list(set(asns))

    except Exception as e:

        logger.warning(f"ASN lookup failed → {e}")

        return []
    
# -----------------------------
# ASN Lookup
# -----------------------------

def get_asn_prefixes(asn):

    logger.info(f"Fetching prefixes for ASN {asn}")

    try:

        url = f"https://api.bgpview.io/asn/{asn}/prefixes"

        r = requests.get(url, timeout=20)

        data = r.json()

        prefixes = []

        for p in data["data"]["ipv4_prefixes"]:
            prefixes.append(p["prefix"])

        return prefixes

    except Exception as e:

        logger.warning(f"ASN prefix lookup failed → {e}")

        return []