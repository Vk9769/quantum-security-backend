import subprocess
import json
import logging
import socket
import ssl
import random
import requests
import os
import tls_client
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("TLSScanner")


# -----------------------------------
# JA3 Fingerprint Rotation (Browsers)
# -----------------------------------

JA3_CLIENTS = [
    "chrome_120",
    "chrome_117",
    "firefox_120",
    "safari_16_0",
    "edge_120"
]


def browser_tls_probe(host):

    try:

        client = random.choice(JA3_CLIENTS)

        session = tls_client.Session(
            client_identifier=client,
            random_tls_extension_order=True
        )

        r = session.get(
            f"https://{host}",
            timeout_seconds=10
        )

        sock = r.connection.sock if hasattr(r.connection, "sock") else None

        if not sock:
            return None

        cipher = sock.cipher()

        der_cert = sock.getpeercert(True)

        cert = x509.load_der_x509_certificate(
            der_cert,
            default_backend()
        )

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        expiry = cert.not_valid_after

        return {
            "tls_version": sock.version(),
            "cipher_suite": cipher[0],
            "key_exchange": cipher[1],
            "certificate_issuer": issuer,
            "certificate_subject": subject,
            "expiry": expiry.isoformat(),
            "signature_algorithm": cert.signature_hash_algorithm.name,
            "key_size": cert.public_key().key_size
        }

    except Exception as e:
        logger.warning(f"Browser TLS probe failed → {host} | {e}")

    return None

def python_tls_socket(host):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=host) as ssock:

                cert_bin = ssock.getpeercert(True)

                cert = x509.load_der_x509_certificate(
                    cert_bin,
                    default_backend()
                )
                expiry = cert.not_valid_after
                return {
                    "tls_version": ssock.version(),
                    "cipher_suite": ssock.cipher()[0],
                    "key_exchange": ssock.cipher()[1],
                    "certificate_issuer": cert.issuer.rfc4514_string(),
                    "certificate_subject": cert.subject.rfc4514_string(),
                    "expiry": expiry.isoformat(),
                    "signature_algorithm": cert.signature_hash_algorithm.name,
                    "key_size": cert.public_key().key_size
                }

    except Exception as e:

        logger.warning(f"Python TLS socket failed → {host} | {e}")

    return None

# -----------------------------------
# ZGrab HTTP TLS (Browser Cipher List)
# -----------------------------------

def zgrab_http_tls(host):

    try:

        ip = socket.gethostbyname(host)

        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "ghcr.io/zmap/zgrab2:latest",
            "http",
            "--port=443",
            "--use-https",
            "--tls-version=TLS12",
            "--cipher-suite=chrome",
            "--alpn=h2,http/1.1"
        ]

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        input_data = f"{ip},{host},443\n"

        stdout, stderr = process.communicate(input=input_data)

        for line in stdout.splitlines():

            if not line.startswith("{"):
                continue

            data = json.loads(line)

            http = data.get("data", {}).get("http")

            if not http:
                continue

            tls = http.get("tls")

            if not tls:
                continue

            handshake = tls["handshake_log"]
            server = handshake["server_hello"]

            cert = handshake["server_certificates"]["certificate"]["parsed"]

            return {
                "tls_version": server.get("version"),
                "cipher_suite": server.get("cipher_suite"),
                "key_exchange": server.get("key_exchange"),
                "certificate_issuer": cert["issuer"]["common_name"],
                "certificate_subject": cert["subject"]["common_name"],
                "signature_algorithm": cert["signature_algorithm"]["name"],
                "key_size": cert["subject_key_info"]["key_length"]
            }

    except Exception as e:
        logger.warning(f"ZGrab HTTP TLS failed → {host} | {e}")

    return None


# -----------------------------------
# ZGrab Raw TLS
# -----------------------------------

def zgrab_tls(host):

    try:

        ip = socket.gethostbyname(host)

        cmd = [
            "docker",
            "run",
            "-i",
            "--rm",
            "ghcr.io/zmap/zgrab2:latest",
            "tls"
        ]

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        input_data = f"{ip},{host},443\n"

        stdout, stderr = process.communicate(input=input_data)

        for line in stdout.splitlines():

            if not line.startswith("{"):
                continue

            data = json.loads(line)

            tls = data.get("data", {}).get("tls")

            if not tls:
                continue

            if tls.get("status") != "success":
                continue

            handshake = tls["result"]["handshake_log"]
            server = handshake["server_hello"]

            return {
                "tls_version": server.get("version"),
                "cipher_suite": server.get("cipher_suite"),
                "key_exchange": server.get("key_exchange")
            }

    except Exception as e:
        logger.warning(f"ZGrab TLS failed → {host} | {e}")

    return None


# -----------------------------------
# OpenSSL Fallback
# -----------------------------------

def openssl_tls(host):

    try:

        cmd = [
            "docker",
            "run",
            "--rm",
            "frapsoft/openssl",
            "s_client",
            "-connect",
            f"{host}:443",
            "-servername",
            host
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout + result.stderr

        tls_version = None
        cipher = None

        for line in output.splitlines():

            if "Protocol  :" in line:
                tls_version = line.split(":")[1].strip()

            if "Cipher    :" in line:
                cipher = line.split(":")[1].strip()

        if tls_version:

            return {
                "tls_version": tls_version,
                "cipher_suite": cipher,
                "key_exchange": None
            }

    except Exception as e:
        logger.warning(f"OpenSSL fallback failed → {host} | {e}")

    return None

def nmap_tls_scan(host):

    cmd = [
        "nmap",
        "-p", "443",
        "--script", "ssl-cert,ssl-enum-ciphers",
        host
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=40
    )

    output = result.stdout

    tls_version = None
    cipher = None
    pqc_algorithm = None

    for line in output.splitlines():

        line = line.strip().lstrip("|").strip()

        if "TLSv1.3" in line:
            tls_version = "TLSv1.3"

        elif "TLSv1.2" in line:
            tls_version = "TLSv1.2"
            
        elif "TLSv1.1" in line:
            tls_version = "TLSv1.1"

        if "TLS_" in line:

            cipher = line.split(" - ")[0].strip()

            if "(" in cipher and ")" in cipher:
                pqc_algorithm = cipher.split("(")[1].replace(")", "")

    if not cipher:
        return None

    return {
        "tls_version": tls_version,
        "cipher_suite": cipher,
        "key_exchange": pqc_algorithm
    }

def shodan_certificate_lookup(host):

    try:

        API = os.getenv("SHODAN_API_KEY")

        url = f"https://api.shodan.io/shodan/host/{host}?key={API}"

        r = requests.get(url, timeout=20)

        data = r.json()

        for item in data.get("data", []):

            ssl_data = item.get("ssl")

            if not ssl_data:
                continue

            cert = ssl_data.get("cert")

            if cert:

                return {
                    "certificate_subject": cert.get("subject"),
                    "certificate_issuer": cert.get("issuer"),
                    "signature_algorithm": cert.get("sig_alg"),
                    "key_size": cert.get("pubkey", {}).get("bits")
                }

    except Exception:
        return None

# -----------------------------------
# CT Log Certificate Fallback
# -----------------------------------

def crtsh_certificate_probe(host):

    try:

        url = f"https://crt.sh/?q=%25.{host}&output=json"

        r = requests.get(
            url,
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if r.status_code != 200:
            return None

        data = r.json()

        if not data:
            return None

        entry = data[0]

        return {
            "certificate_subject": entry.get("common_name"),
            "certificate_issuer": entry.get("issuer_name"),
            "signature_algorithm": entry.get("signature_algorithm"),
            "key_size": None
        }

    except Exception as e:

        logger.warning(f"CT log lookup failed → {host} | {e}")

    return None

def ct_log_certificate_probe(host):

    sources = [
        f"https://crt.sh/?q=%25.{host}&output=json",
        f"https://ct.cloudflare.com/logs/cirrus/search?domain={host}",
        f"https://api.certspotter.com/v1/issuances?domain={host}&expand=dns_names",
        f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain={host}"
    ]

    for url in sources:

        try:

            r = requests.get(
                url,
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            if r.status_code != 200:
                continue

            data = r.json()

            if not data:
                continue

            entry = data[0]

            return {
                "certificate_subject": entry.get("common_name") or entry.get("subject"),
                "certificate_issuer": entry.get("issuer_name") or entry.get("issuer"),
                "signature_algorithm": entry.get("signature_algorithm"),
                "key_size": entry.get("key_size")
            }

        except Exception:
            continue

    return None

def censys_certificate_lookup(host):

    try:


        API_TOKEN = os.getenv("CENSYS_API_TOKEN")

        url = f"https://search.censys.io/api/v2/hosts/{host}"

        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Accept": "application/json"
        }

        r = requests.get(url, headers=headers, timeout=20)

        if r.status_code != 200:
            return None

        data = r.json()

        services = data.get("result", {}).get("services", [])

        for service in services:

            tls = service.get("tls")

            if not tls:
                continue

            cert = tls.get("certificates", {}).get("leaf_data")

            if not cert:
                continue

            return {
                "certificate_subject": cert.get("subject_dn"),
                "certificate_issuer": cert.get("issuer_dn"),
                "signature_algorithm": cert.get("signature_algorithm"),
                "key_size": cert.get("public_key", {}).get("size")
            }

    except Exception:
        return None
    
    
PROXIES = [
    "http://aws-proxy-ip:8080",
    "http://azure-proxy-ip:8080",
    "http://gcp-proxy-ip:8080"
]


def cloud_tls_probe(host):

    try:

        proxy = random.choice(PROXIES)

        r = requests.get(
            f"https://{host}",
            proxies={"https": proxy},
            timeout=10,
            verify=False
        )

        return True

    except Exception:
        return None
    
def detect_pqc(cipher):

    if not cipher:
        return "UNKNOWN"

    pqc_algorithms = [
        "MLKEM",
        "KYBER",
        "FRODOKEM",
        "BIKE",
        "NTRU"
    ]

    for algo in pqc_algorithms:

        if algo in cipher.upper():
            return "POST_QUANTUM"

    return "CLASSICAL"

# -----------------------------------
# MASTER TLS SCANNER
# -----------------------------------

def scan_tls(host):

    logger.info(f"TLS scan starting → {host}")

    # 1 Browser JA3 probe
    result = browser_tls_probe(host)

    if result:
        logger.info("TLS success via Browser JA3")
        return result

    # 2 Python TLS socket
    result = python_tls_socket(host)

    if result:
        logger.info("TLS success via Python socket")
        return result

    # 3 Cloud probe
    cloud = cloud_tls_probe(host)

    if cloud:
        logger.info("Cloud probe succeeded")

    # 4 ZGrab HTTP TLS
    result = zgrab_http_tls(host)

    if result:
        logger.info("TLS success via ZGrab HTTP")
        return result

    # 5 ZGrab TLS
    result = zgrab_tls(host)

    if result:
        logger.info("TLS success via ZGrab TLS")
        return result

    # 6 Nmap SSL enumeration
    tls = nmap_tls_scan(host)

    if tls:

        pqc_status = detect_pqc(tls["cipher_suite"])

        tls["quantum_security"] = pqc_status

        logger.info(f"TLS discovered via Nmap → {pqc_status}")

        return tls

    # 7 OpenSSL
    result = openssl_tls(host)

    if result:
        logger.info("TLS success via OpenSSL")
        return result

    # 8 Passive lookup (Censys)
    cert = censys_certificate_lookup(host)

    if cert:
        logger.info("Certificate found via Censys")
        return {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        }

    # 9 Passive lookup (Shodan)
    cert = shodan_certificate_lookup(host)

    if cert:
        logger.info("Certificate found via Shodan")
        return {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        }

    # 10 CT logs
    cert = ct_log_certificate_probe(host)

    if cert:
        logger.info("Certificate found via CT logs")
        return {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        }

    # 11 crt.sh fallback
    cert = crtsh_certificate_probe(host)

    if cert:
        logger.info("Certificate found via crt.sh")
        return {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        }

    logger.error("TLS scan completely failed")

    return {
        "tls_version": "UNKNOWN",
        "cipher_suite": "UNKNOWN",
        "key_exchange": None
    }