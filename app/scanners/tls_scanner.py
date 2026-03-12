import ssl
import socket
import logging

logger = logging.getLogger("TLSScanner")


def scan_tls(host, port=443):

    try:

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=3) as sock:

            with context.wrap_socket(sock, server_hostname=host) as tls:

                cipher = tls.cipher()

                return {
                    "tls_version": tls.version(),
                    "cipher_suite": cipher[0],
                    "key_exchange": cipher[1]
                }

    except Exception:

        logger.debug(f"TLS scan failed → {host}:{port}")
        return None