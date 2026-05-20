import os
import requests
import logging
import socket
import ipaddress
from typing import Optional, List, Dict, Any
from app.utils.dns_resolver import resolve_domain

logger = logging.getLogger("ASNScanner")

IPINFO_API = "https://api.ipinfo.io"
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "QuantumSecurityPlatform/1.0"
})

_IPINFO_CACHE: Dict[str, Dict[str, Any]] = {}


# -----------------------------------
# Helpers
# -----------------------------------

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def resolve_ip(domain: str) -> Optional[str]:
    ip = resolve_domain(domain)

    if ip:
        logger.info(f"Resolved {domain} → {ip}")
    else:
        logger.warning(f"DNS resolution failed → {domain}")

    return ip


def clear_ipinfo_cache():
    _IPINFO_CACHE.clear()
    logger.info("IPinfo cache cleared")


def _normalize_ipinfo_response(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data:
        return {}

    # Rich /lookup format
    if "as" in data or "geo" in data:
        as_block = data.get("as", {}) or {}
        geo_block = data.get("geo", {}) or {}

        return {
            "ip": data.get("ip"),
            "asn": as_block.get("asn"),
            "as_name": as_block.get("name"),
            "as_domain": as_block.get("domain"),
            "as_type": as_block.get("type"),
            "route": data.get("route") or as_block.get("route"),
            "country_code": geo_block.get("country_code"),
            "city": geo_block.get("city"),
            "region": geo_block.get("region"),
            "company": as_block.get("name"),
            "raw": data
        }

    # Lite format
    return {
        "ip": data.get("ip"),
        "asn": data.get("asn"),
        "as_name": data.get("as_name") or data.get("name"),
        "as_domain": data.get("as_domain") or data.get("domain"),
        "as_type": data.get("as_type"),
        "route": data.get("as_route") or data.get("route"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "region": data.get("region"),
        "company": data.get("company"),
        "raw": data
    }


def _fetch_ipinfo(url: str) -> Optional[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"}
    r = SESSION.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()


def ipinfo_lookup(ip: str, force_refresh: bool = False) -> Optional[Dict[str, Any]]:
    if not ip:
        return None

    if not force_refresh and ip in _IPINFO_CACHE:
        return _IPINFO_CACHE[ip]

    # always try rich lookup first
    urls = [
        f"{IPINFO_API}/lookup/{ip}",
        f"{IPINFO_API}/lite/{ip}"
    ]

    for url in urls:
        try:
            data = _fetch_ipinfo(url)
            normalized = _normalize_ipinfo_response(data)

            # if lookup returned richer fields, cache that
            _IPINFO_CACHE[ip] = normalized
            logger.info(
                f"IPinfo success → {ip} | endpoint={url} | "
                f"asn={normalized.get('asn')} | "
                f"name={normalized.get('as_name')} | "
                f"type={normalized.get('as_type')} | "
                f"route={normalized.get('route')}"
            )
            return normalized

        except requests.exceptions.HTTPError as e:
            logger.warning(f"IPinfo HTTP error → {url} | {e}")
            continue
        except requests.exceptions.RequestException as e:
            logger.warning(f"IPinfo request failed → {url} | {e}")
            continue
        except ValueError as e:
            logger.warning(f"Invalid JSON from IPinfo → {url} | {e}")
            continue

    return None


# -----------------------------------
# ASN functions
# -----------------------------------

def get_asn_from_ip(ip: str) -> Optional[int]:
    logger.info(f"Finding ASN for IP → {ip}")

    data = ipinfo_lookup(ip)
    if not data:
        return None

    asn_value = data.get("asn")
    if not asn_value:
        return None

    asn_digits = str(asn_value).upper().replace("AS", "").strip()
    if asn_digits.isdigit():
        asn = int(asn_digits)
        logger.info(f"Resolved IP {ip} → ASN {asn}")
        return asn

    return None


def get_asn_org(ip: str) -> Optional[str]:
    logger.info(f"Finding ASN org for IP → {ip}")

    data = ipinfo_lookup(ip)
    if not data:
        return None

    asn = data.get("asn")
    name = data.get("as_name")

    if asn and name:
        org = f"{asn} {name}"
        logger.info(f"Resolved IP {ip} → Org {org}")
        return org

    return name


def get_asn_details_from_ip(ip: str) -> Dict[str, Any]:
    logger.info(f"Fetching ASN details via IPinfo → {ip}")

    data = ipinfo_lookup(ip)
    if not data:
        return {}

    result = {
        "asn": data.get("asn"),
        "name": data.get("as_name"),
        "description": data.get("as_domain"),
        "country_code": data.get("country_code"),
        "rir_name": None,
        "type": data.get("as_type"),
        "domain": data.get("as_domain"),
        "route": data.get("route"),
        "company": data.get("company"),
        "city": data.get("city"),
        "region": data.get("region"),
    }

    logger.info(f"ASN details fetched → {result}")
    return result


def get_asn_prefixes(ip: str) -> List[str]:
    logger.info(f"Fetching prefixes for IP → {ip}")

    data = ipinfo_lookup(ip)
    if not data:
        return [f"{ip}/32"] if ip else []

    route = data.get("route")
    if route:
        logger.info(f"Using ASN route prefix → {route}")
        return [route]

    # fallback: derive /24 from IP if no route available
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        logger.info(f"Using derived prefix → {network}")
        return [str(network)]
    except Exception:
        prefix = f"{ip}/32"
        logger.info(f"Using fallback prefix → {prefix}")
        return [prefix]


def get_asn(domain: str) -> List[int]:
    logger.info(f"Finding ASN for domain → {domain}")

    ip = resolve_ip(domain)
    if not ip:
        return []

    asn = get_asn_from_ip(ip)
    return [asn] if asn else []


def enrich_asn(target: str) -> Dict[str, Any]:
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

        # force refresh if you suspect stale cached lite response
        data = ipinfo_lookup(ip, force_refresh=True)
        if not data:
            return result

        asn_value = data.get("asn")
        if asn_value:
            asn_digits = str(asn_value).upper().replace("AS", "").strip()
            if asn_digits.isdigit():
                result["primary_asn"] = int(asn_digits)
                result["asns"] = [int(asn_digits)]

        if data.get("asn") and data.get("as_name"):
            result["org"] = f"{data['asn']} {data['as_name']}"
        else:
            result["org"] = data.get("as_name")

        result["asn_details"] = {
            "asn": data.get("asn"),
            "name": data.get("as_name"),
            "description": data.get("as_domain"),
            "country_code": data.get("country_code"),
            "rir_name": None,
            "type": data.get("as_type"),
            "domain": data.get("as_domain"),
            "route": data.get("route"),
            "company": data.get("company"),
            "city": data.get("city"),
            "region": data.get("region"),
        }

        route = data.get("route")
        if route:
            result["prefixes"] = [route]
        else:
            try:
                result["prefixes"] = [str(ipaddress.ip_network(f"{ip}/24", strict=False))]
            except Exception:
                result["prefixes"] = [f"{ip}/32"]

        return result

    except Exception as e:
        logger.warning(f"ASN enrichment failed for {target} → {e}")
        return result