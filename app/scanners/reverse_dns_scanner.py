import socket
import ipaddress
import logging
from typing import List, Optional

logger = logging.getLogger("ReverseDNS")


def reverse_dns(prefix: str) -> List[str]:
    """
    Reverse DNS sweep for all usable hosts in a subnet.
    Example:
        reverse_dns("192.168.1.0/24")
    Returns:
        ["host1.example.com", "host2.example.com", ...]
    """
    discovered = []

    try:
        net = ipaddress.ip_network(prefix, strict=False)

    except Exception as e:
        logger.warning(f"Invalid network prefix → {prefix} | {e}")
        return discovered

    for ip in net.hosts():
        try:
            host = socket.gethostbyaddr(str(ip))[0]

            if host and host not in discovered:
                discovered.append(host)

        except Exception:
            continue

    logger.info(f"Reverse DNS subnet sweep complete → {prefix} | found={len(discovered)}")
    return discovered


def resolve_ip(host: str) -> Optional[str]:
    """
    Resolve hostname to IPv4 address.
    Example:
        resolve_ip("example.com") -> "93.184.216.34"
    """
    try:
        ip = socket.gethostbyname(host)
        return ip
    except Exception as e:
        logger.warning(f"Host to IP resolution failed → {host} | {e}")
        return None


def reverse_dns_lookup(host_or_ip: str) -> Optional[str]:
    """
    Reverse DNS lookup for a single host or IP.
    Accepts:
        - domain: example.com
        - ip: 8.8.8.8

    Returns:
        PTR hostname if available, else None
    """
    try:
        # If input is already an IP
        try:
            ipaddress.ip_address(host_or_ip)
            ip = host_or_ip
        except ValueError:
            ip = resolve_ip(host_or_ip)

        if not ip:
            return None

        ptr = socket.gethostbyaddr(ip)[0]

        logger.info(f"Reverse DNS lookup success → {host_or_ip} | {ip} → {ptr}")
        return ptr

    except Exception as e:
        logger.warning(f"Reverse DNS lookup failed → {host_or_ip} | {e}")
        return None


def reverse_dns_detailed(prefix: str) -> List[dict]:
    """
    Detailed reverse DNS sweep for a subnet.
    Returns list like:
    [
        {"ip": "8.8.8.8", "hostname": "dns.google"},
        ...
    ]
    """
    discovered = []

    try:
        net = ipaddress.ip_network(prefix, strict=False)

    except Exception as e:
        logger.warning(f"Invalid network prefix → {prefix} | {e}")
        return discovered

    for ip in net.hosts():
        ip_str = str(ip)

        try:
            host = socket.gethostbyaddr(ip_str)[0]
            discovered.append({
                "ip": ip_str,
                "hostname": host
            })

        except Exception:
            continue

    logger.info(f"Detailed reverse DNS sweep complete → {prefix} | found={len(discovered)}")
    return discovered