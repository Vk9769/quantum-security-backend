import socket
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("PortScanner")

COMMON_PORTS = [
21,
22,
25,
80,
443,
3306,
5432,
6379,
8080,
8443
]


def scan_port(host, port):

    try:
        ip = socket.gethostbyname(host)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            logger.info(f"OPEN → {host}:{port}")
            return port

    except Exception:
        pass

    return None


def scan_ports(host):

    logger.info(f"Starting port scan → {host}")

    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:

        results = executor.map(lambda p: scan_port(host, p), COMMON_PORTS)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports