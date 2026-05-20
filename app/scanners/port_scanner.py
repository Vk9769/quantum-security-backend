import subprocess
import socket
import logging
import re
import xml.etree.ElementTree as ET
from app.utils.dns_resolver import resolve_all_ips

logger = logging.getLogger("PortScanner")


# -----------------------------------
# DNS Resolver
# -----------------------------------

def resolve_host(host):
    ips = resolve_all_ips(host)

    if ips:
        logger.info(f"Resolved {host} → {ips}")
    else:
        logger.warning(f"DNS resolution failed → {host}")

    return ips


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
        443, 80, 22, 21, 25, 53,
        110, 143, 3306, 5432,
        6379, 8080, 8443
    ]

    open_ports = []

    for port in COMMON_PORTS:

        success = False

        for _ in range(2):  # 🔁 retry
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)   # 🔥 increased timeout
                    result = sock.connect_ex((ip, port))

                    if result == 0:
                        success = True
                        break
            except:
                pass

        if success:
            open_ports.append(port)

    # 🔥 FORCE HTTPS DETECTION (CRITICAL FIX)
    if 443 not in open_ports:
        try:
            with socket.create_connection((ip, 443), timeout=3):
                open_ports.append(443)
                logger.info(f"Forced detect → 443 open → {ip}")
        except:
            pass

    return open_ports


# -----------------------------------
# Parse Nmap XML
# -----------------------------------

def parse_nmap_xml(xml_output):

    open_ports = []

    try:
        root = ET.fromstring(xml_output)

        for host in root.findall("host"):
            for port in host.findall(".//port"):

                state = port.find("state").get("state")

                if state == "open":
                    port_id = int(port.get("portid"))
                    open_ports.append(port_id)

    except Exception as e:
        logger.warning(f"XML parsing failed → {e}")

    return open_ports


# -----------------------------------
# Nmap Validation
# -----------------------------------

def nmap_validate(ip, ports):

    try:
        if not ports:
            return []

        port_str = ",".join(map(str, ports))

        logger.info(f"Running Nmap validation → {ip} | Ports: {port_str}")

        cmd = [
            "docker", "run", "--rm",
            "instrumentisto/nmap",
            "-p", port_str,
            "-sT",
            "-Pn",
            "-T4",
            "-oX", "-",
            ip
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        if not result.stdout:
            logger.warning("Empty Nmap output")
            return []

        return parse_nmap_xml(result.stdout)

    except Exception as e:
        logger.warning(f"Nmap validation failed → {e}")
        return []


# -----------------------------------
# 🔥 REAL SERVICE VALIDATION (FIX)
# -----------------------------------

def validate_real_service(ip, port):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect((ip, port))

            # Try small probe
            try:
                sock.send(b"\r\n")
                data = sock.recv(32)

                if data:
                    return True
            except:
                return True  # connection success is enough sometimes

    except Exception:
        pass

    return False


# -----------------------------------
# HTTP Validation (extra accuracy)
# -----------------------------------

def http_probe(host, port):
    try:
        import requests
        url = f"http://{host}:{port}"
        r = requests.get(url, timeout=3)
        return True
    except:
        return False


# -----------------------------------
# Master port scanner (FINAL)
# -----------------------------------

def scan_ports(host):

    logger.info(f"🔥 FAST SCAN START → {host}")

    ips = resolve_host(host)

    if not ips:
        logger.warning(f"Skipping scan (DNS failed) → {host}")
        return []

    final_ports = set()

    for ip in ips:

        logger.info(f"👉 Scanning IP → {ip}")

        # ✅ ONLY FAST PYTHON SCAN (NO DOCKER)
        ports = python_fallback(ip)

        # 🔥 validate real service
        validated_ports = []

        for p in ports:
            if validate_real_service(ip, p):
                validated_ports.append(p)

        ports = validated_ports

        logger.info(f"⚡ Ports found → {ip} → {ports}")

        final_ports.update(ports)

    logger.info(f"✅ FINAL PORTS → {host} → {list(final_ports)}")

    return sorted(list(final_ports))