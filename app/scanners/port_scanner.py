import subprocess
import socket
import logging
import re
import dns.resolver

logger = logging.getLogger("PortScanner")


# -----------------------------------
# DNS Resolver
# -----------------------------------

def resolve_host(host):
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=5)
        ips = [a.to_text() for a in answers]

        logger.info(f"Resolved {host} → {ips}")

        return ips

    except Exception as e:
        logger.warning(f"DNS resolution failed → {host} | {e}")
        return []


# -----------------------------------
# Masscan (fast scanner)
# -----------------------------------

def masscan_scan(ip):

    try:

        logger.info(f"Running masscan → {ip}")

        cmd = [
            "docker",
            "run",
            "--rm",
            "masscan",
            ip,
            "-p1-1000",
            "--rate",
            "1000"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        ports = set()

        for line in result.stdout.splitlines():

            match = re.search(r"Discovered open port (\d+)/tcp", line)

            if match:
                ports.add(int(match.group(1)))

        return sorted(list(ports))

    except subprocess.TimeoutExpired:

        logger.warning("Masscan timeout")

        return []

    except Exception as e:

        logger.warning(f"Masscan failed → {e}")

        return []


# -----------------------------------
# Python fallback scanner
# -----------------------------------

def python_fallback(ip):

    COMMON_PORTS = [
        21,22,25,53,80,110,143,443,
        3306,5432,6379,8080,8443
    ]

    open_ports = []

    for port in COMMON_PORTS:

        try:

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

                sock.settimeout(1)

                result = sock.connect_ex((ip, port))

                if result == 0:
                    open_ports.append(port)

        except Exception:
            pass

    return open_ports


# -----------------------------------
# Master port scanner
# -----------------------------------

def scan_ports(host):

    logger.info(f"Starting enterprise port scan → {host}")

    # Resolve domain
    ips = resolve_host(host)

    if not ips:
        logger.warning(f"Skipping scan (DNS failed) → {host}")
        return []

    all_ports = set()

    # Scan every IP
    for ip in ips:

        # Run masscan
        ports = masscan_scan(ip)

        if ports:
            logger.info(f"Masscan discovered {len(ports)} ports on {ip}")
            all_ports.update(ports)
            continue

        # Fallback scanner
        logger.warning(f"Masscan failed → fallback Python scanner ({ip})")

        ports = python_fallback(ip)

        if ports:
            logger.info(f"Python scanner discovered {len(ports)} ports on {ip}")
            all_ports.update(ports)

    return sorted(list(all_ports))