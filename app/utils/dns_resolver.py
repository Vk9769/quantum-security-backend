# app/utils/dns_resolver.py

import dns.resolver
import socket
import logging

logger = logging.getLogger("DNSResolver")

# -----------------------------------
# Primary Resolver (Public DNS)
# -----------------------------------
resolver = dns.resolver.Resolver()

resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google + Cloudflare
resolver.timeout = 3
resolver.lifetime = 5


# -----------------------------------
# Resolve Domain → IP
# -----------------------------------
def resolve_domain(domain: str):
    """
    Resolve domain to IPv4 address using:
    1. Public DNS (primary)
    2. System DNS (fallback)
    """

    if not domain:
        return None

    domain = domain.strip().lower()

    # -----------------------------
    # PRIMARY: Public DNS
    # -----------------------------
    try:
        answers = resolver.resolve(domain, "A")
        ip = answers[0].to_text()

        logger.info(f"DNS resolved (public) → {domain} → {ip}")
        return ip

    except Exception as e:
        logger.warning(f"Public DNS failed → {domain} | {e}")

    # -----------------------------
    # FALLBACK: System DNS
    # -----------------------------
    try:
        ip = socket.gethostbyname(domain)

        logger.info(f"DNS resolved (fallback) → {domain} → {ip}")
        return ip

    except Exception as e:
        logger.error(f"System DNS failed → {domain} | {e}")

    return None


# -----------------------------------
# Resolve ALL IPs (Optional Advanced)
# -----------------------------------
def resolve_all_ips(domain: str):
    """
    Returns all A records for a domain
    """

    try:
        answers = resolver.resolve(domain, "A")
        ips = [r.to_text() for r in answers]

        logger.info(f"Resolved multiple IPs → {domain} → {ips}")
        return ips

    except Exception as e:
        logger.warning(f"Multi-IP resolution failed → {domain} | {e}")
        return []


# -----------------------------------
# Check if Domain Resolves
# -----------------------------------
def is_resolvable(domain: str) -> bool:
    return resolve_domain(domain) is not None