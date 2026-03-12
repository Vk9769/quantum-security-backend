import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_certificate_info(host):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:

                der_cert = ssock.getpeercert(binary_form=True)

                if not der_cert:
                    return None

                cert = x509.load_der_x509_certificate(
                    der_cert,
                    default_backend()
                )

                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()

                expiry = cert.not_valid_after.date()

                cipher = ssock.cipher()

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "expiry": expiry,
                    "signature_algorithm": cipher[0],
                    "key_size": cert.public_key().key_size
                }

    except Exception:
        return None