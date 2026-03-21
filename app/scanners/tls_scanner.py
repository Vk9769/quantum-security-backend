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


# -----------------------------------
# Helpers
# -----------------------------------

def safe_signature_algorithm(cert):
    try:
        if cert.signature_algorithm_oid and cert.signature_algorithm_oid._name:
            return cert.signature_algorithm_oid._name
    except Exception:
        pass

    try:
        if cert.signature_hash_algorithm and cert.signature_hash_algorithm.name:
            return cert.signature_hash_algorithm.name
    except Exception:
        pass

    return None


def safe_public_key_type(cert):
    try:
        return cert.public_key().__class__.__name__
    except Exception:
        return None


def safe_public_key_size(cert):
    try:
        return cert.public_key().key_size
    except Exception:
        return None


def detect_pqc(value):
    if not value:
        return "CLASSICAL_OR_UNCONFIRMED"

    text = str(value).upper()

    pqc_algorithms = [
        "MLKEM",
        "KYBER",
        "FRODOKEM",
        "BIKE",
        "NTRU",
        "HYBRID"
    ]

    for algo in pqc_algorithms:
        if algo in text:
            return "POST_QUANTUM_OR_HYBRID"

    return "CLASSICAL"


def merge_results(base, extra):
    if not extra:
        return base

    for k, v in extra.items():
        if v is not None and (base.get(k) is None or base.get(k) in ["UNKNOWN", [], ""]):
            base[k] = v

    return base


# -----------------------------------
# Browser JA3 probe
# -----------------------------------

def browser_tls_probe(host):
    try:
        client = random.choice(JA3_CLIENTS)

        session = tls_client.Session(
            client_identifier=client,
            random_tls_extension_order=True
        )

        session.get(
            f"https://{host}",
            timeout_seconds=10
        )

        # tls_client does not reliably expose the raw socket in a portable way.
        # So use this probe only as proof browser-like TLS works, then fallback
        # to Python socket for actual cert/cipher extraction.
        logger.info(f"Browser JA3 HTTPS probe succeeded → {host}")

        return {
            "browser_probe": True
        }

    except Exception as e:
        logger.warning(f"Browser TLS probe failed → {host} | {e}")

    return None


# -----------------------------------
# Python TLS socket
# -----------------------------------

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

                expiry = cert.not_valid_after_utc
                cipher = ssock.cipher() or (None, None, None)

                return {
                    "tls_version": ssock.version(),
                    "cipher_suite": cipher[0],
                    "cipher_protocol": cipher[1],
                    "cipher_bits": cipher[2],
                    "key_exchange": None,   # Python ssl usually does not expose negotiated group
                    "certificate_issuer": cert.issuer.rfc4514_string(),
                    "certificate_subject": cert.subject.rfc4514_string(),
                    "expiry": expiry.isoformat(),
                    "signature_algorithm": safe_signature_algorithm(cert),
                    "key_size": safe_public_key_size(cert),
                    "public_key_type": safe_public_key_type(cert),
                    "quantum_security": detect_pqc(cipher[0])
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

            handshake = tls.get("handshake_log", {})
            server = handshake.get("server_hello", {})
            cert = handshake.get("server_certificates", {}).get("certificate", {}).get("parsed", {})

            issuer_cn = None
            subject_cn = None
            sig_alg = None
            key_size = None

            try:
                issuer_cn = cert.get("issuer", {}).get("common_name")
            except Exception:
                pass

            try:
                subject_cn = cert.get("subject", {}).get("common_name")
            except Exception:
                pass

            try:
                sig_alg = cert.get("signature_algorithm", {}).get("name")
            except Exception:
                pass

            try:
                key_size = cert.get("subject_key_info", {}).get("key_length")
            except Exception:
                pass

            result = {
                "tls_version": server.get("version"),
                "cipher_suite": server.get("cipher_suite"),
                "key_exchange": server.get("key_exchange"),
                "certificate_issuer": issuer_cn,
                "certificate_subject": subject_cn,
                "signature_algorithm": sig_alg,
                "key_size": key_size,
                "quantum_security": detect_pqc(
                    f"{server.get('key_exchange', '')} {server.get('cipher_suite', '')}"
                )
            }

            return result

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

            handshake = tls.get("result", {}).get("handshake_log", {})
            server = handshake.get("server_hello", {})

            result = {
                "tls_version": server.get("version"),
                "cipher_suite": server.get("cipher_suite"),
                "key_exchange": server.get("key_exchange"),
                "quantum_security": detect_pqc(
                    f"{server.get('key_exchange', '')} {server.get('cipher_suite', '')}"
                )
            }

            return result

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
            "alpine:latest",
            "sh",
            "-c",
            (
                f"apk add --no-cache openssl >/dev/null 2>&1 && "
                f"openssl s_client "
                f"-connect {host}:443 "
                f"-servername {host} "
                f"-showcerts "
                f"-tls1_3"
            )
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=40
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        issuer = None
        subject = None
        tls_version = None
        cipher = None
        key_size = None
        signature_algorithm = None
        expiry = None
        key_exchange = None

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("subject="):
                subject = line.replace("subject=", "").strip()

            elif line.startswith("issuer="):
                issuer = line.replace("issuer=", "").strip()

            elif line.startswith("Protocol  :"):
                tls_version = line.split(":", 1)[1].strip()

            elif line.startswith("Protocol:"):
                tls_version = line.split(":", 1)[1].strip()

            elif line.startswith("Cipher    :"):
                cipher = line.split(":", 1)[1].strip()

            elif line.startswith("Cipher is"):
                cipher = line.split("Cipher is", 1)[1].strip()

            elif "Server Temp Key:" in line:
                key_exchange = line.split(":", 1)[1].strip()

            elif "Negotiated TLS1.3 group:" in line:
                key_exchange = line.split(":", 1)[1].strip()

            elif "TLS1.3 group:" in line:
                key_exchange = line.split(":", 1)[1].strip()

            elif "Peer signature type:" in line:
                signature_algorithm = line.split(":", 1)[1].strip()

            elif "sigalg:" in line.lower():
                try:
                    signature_algorithm = line.split("sigalg:", 1)[1].strip().split()[0]
                except Exception:
                    pass

            elif "Server public key is" in line and "bit" in line:
                digits = "".join(ch for ch in line if ch.isdigit())
                if digits:
                    key_size = int(digits)

            elif "PKEY:" in line and "bit" in line:
                digits = "".join(ch for ch in line if ch.isdigit())
                if digits:
                    key_size = int(digits)

            elif "NotAfter:" in line:
                expiry = line.split("NotAfter:", 1)[1].strip()

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher,
            "key_exchange": key_exchange,
            "certificate_subject": subject,
            "certificate_issuer": issuer,
            "signature_algorithm": signature_algorithm,
            "key_size": key_size,
            "expiry": expiry,
            "quantum_security": detect_pqc(
                f"{key_exchange or ''} {cipher or ''}"
            )
        }

    except Exception as e:
        logger.warning(f"OpenSSL TLS failed → {host} | {e}")

    return None

# -----------------------------------
# Nmap TLS Enumeration
# -----------------------------------

def nmap_tls_scan(host):
    try:
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

        output = result.stdout or ""

        tls_version = None
        cipher = None
        pqc_algorithm = None
        signature_algorithm = None

        for line in output.splitlines():
            line = line.strip()

            if "TLSv1.3:" in line:
                tls_version = "TLSv1.3"
            elif "TLSv1.2:" in line and not tls_version:
                tls_version = "TLSv1.2"

            if "TLS_" in line:
                cipher = line.replace("|", "").strip().split(" - ")[0]

                if "(" in line and ")" in line:
                    try:
                        pqc_algorithm = line.split("(", 1)[1].split(")", 1)[0]
                    except Exception:
                        pass

            if "Signature Algorithm:" in line:
                try:
                    signature_algorithm = line.split("Signature Algorithm:", 1)[1].strip()
                except Exception:
                    pass

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher,
            "key_exchange": pqc_algorithm,
            "signature_algorithm": signature_algorithm,
            "quantum_security": detect_pqc(
                (pqc_algorithm or "") + " " + (cipher or "")
            )
        }

    except Exception as e:
        logger.warning(f"Nmap TLS scan failed → {host} | {e}")
        return None


# -----------------------------------
# Passive certificate lookups
# -----------------------------------

def shodan_certificate_lookup(host):
    try:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return None

        url = f"https://api.shodan.io/shodan/host/{host}?key={api_key}"
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
        api_token = os.getenv("CENSYS_API_TOKEN")
        if not api_token:
            return None

        url = f"https://search.censys.io/api/v2/hosts/{host}"

        headers = {
            "Authorization": f"Bearer {api_token}",
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


# -----------------------------------
# Cloud probe
# -----------------------------------

PROXIES = [
    "http://aws-proxy-ip:8080",
    "http://azure-proxy-ip:8080",
    "http://gcp-proxy-ip:8080"
]


def cloud_tls_probe(host):
    try:
        proxy = random.choice(PROXIES)

        requests.get(
            f"https://{host}",
            proxies={"https": proxy},
            timeout=10,
            verify=False
        )

        return True

    except Exception:
        return None


# -----------------------------------
# Protocol support probing
# -----------------------------------

def probe_supported_tls_versions(host):
    supported = []

    versions = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ]

    tls13_supported = hasattr(ssl.TLSVersion, "TLSv1_3")
    if tls13_supported:
        versions.append(("TLSv1.3", ssl.TLSVersion.TLSv1_3))

    for version_name, version_obj in versions:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version_obj
            context.maximum_version = version_obj

            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    supported.append(version_name)

        except Exception:
            pass

    return supported


# -----------------------------------
# MASTER TLS SCANNER
# -----------------------------------

def scan_tls(host):
    logger.info(f"TLS scan starting → {host}")

    final_result = {
        "tls_version": None,
        "supported_tls_versions": [],
        "cipher_suite": None,
        "cipher_protocol": None,
        "cipher_bits": None,
        "key_exchange": None,
        "certificate_issuer": None,
        "certificate_subject": None,
        "expiry": None,
        "signature_algorithm": None,
        "key_size": None,
        "public_key_type": None,
        "quantum_security": "CLASSICAL_OR_UNCONFIRMED",
        "browser_probe": False
    }

    # 1 Browser JA3 probe
    browser_result = browser_tls_probe(host)
    if browser_result:
        final_result["browser_probe"] = True
        logger.info("TLS browser-style probe succeeded")

    # 2 Python TLS socket
    socket_result = python_tls_socket(host)
    if socket_result:
        logger.info("TLS success via Python socket")
        final_result = merge_results(final_result, socket_result)

    # 3 OpenSSL enrichment
    openssl_result = openssl_tls(host)
    if openssl_result:
        logger.info("TLS enrichment via OpenSSL")
        final_result = merge_results(final_result, openssl_result)

    # 4 supported protocol versions
    try:
        final_result["supported_tls_versions"] = probe_supported_tls_versions(host)
    except Exception as e:
        logger.warning(f"TLS protocol support probe failed → {host} | {e}")

    # If we already got strong active results, return now
    if final_result.get("tls_version") or final_result.get("cipher_suite"):
        final_result["quantum_security"] = detect_pqc(
            f"{final_result.get('key_exchange', '')} {final_result.get('cipher_suite', '')}"
        )
        return final_result

    # 5 Cloud probe
    cloud = cloud_tls_probe(host)
    if cloud:
        logger.info("Cloud probe succeeded")

    # 6 ZGrab HTTP TLS
    result = zgrab_http_tls(host)
    if result:
        logger.info("TLS success via ZGrab HTTP")
        final_result = merge_results(final_result, result)
        final_result["quantum_security"] = detect_pqc(
            f"{final_result.get('key_exchange', '')} {final_result.get('cipher_suite', '')}"
        )
        return final_result

    # 7 ZGrab TLS
    result = zgrab_tls(host)
    if result:
        logger.info("TLS success via ZGrab TLS")
        final_result = merge_results(final_result, result)
        final_result["quantum_security"] = detect_pqc(
            f"{final_result.get('key_exchange', '')} {final_result.get('cipher_suite', '')}"
        )
        return final_result

    # 8 Nmap SSL enumeration
    tls = nmap_tls_scan(host)
    if tls:
        logger.info("TLS discovered via Nmap")
        final_result = merge_results(final_result, tls)

        cert = openssl_tls(host)
        if cert:
            final_result = merge_results(final_result, cert)

        final_result["quantum_security"] = detect_pqc(
            final_result.get("key_exchange") or final_result.get("cipher_suite")
        )
        return final_result

    # 9 Passive lookup (Censys)
    cert = censys_certificate_lookup(host)
    if cert:
        logger.info("Certificate found via Censys")
        final_result = merge_results(final_result, {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        })
        return final_result

    # 10 Passive lookup (Shodan)
    cert = shodan_certificate_lookup(host)
    if cert:
        logger.info("Certificate found via Shodan")
        final_result = merge_results(final_result, {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        })
        return final_result

    # 11 CT logs
    cert = ct_log_certificate_probe(host)
    if cert:
        logger.info("Certificate found via CT logs")
        final_result = merge_results(final_result, {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        })
        return final_result

    # 12 crt.sh fallback
    cert = crtsh_certificate_probe(host)
    if cert:
        logger.info("Certificate found via crt.sh")
        final_result = merge_results(final_result, {
            "tls_version": "UNKNOWN",
            "cipher_suite": "UNKNOWN",
            "key_exchange": None,
            **cert
        })
        return final_result

    logger.error("TLS scan completely failed")

    return {
        "tls_version": "UNKNOWN",
        "supported_tls_versions": final_result.get("supported_tls_versions", []),
        "cipher_suite": "UNKNOWN",
        "cipher_protocol": None,
        "cipher_bits": None,
        "key_exchange": None,
        "certificate_issuer": None,
        "certificate_subject": None,
        "expiry": None,
        "signature_algorithm": None,
        "key_size": None,
        "public_key_type": None,
        "quantum_security": "CLASSICAL_OR_UNCONFIRMED",
        "browser_probe": final_result.get("browser_probe", False)
    }