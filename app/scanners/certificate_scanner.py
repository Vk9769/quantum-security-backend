import ssl
import socket
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("CertificateScanner")


def get_certificate_info(host):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=8) as sock:
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
                expiry = cert.not_valid_after_utc.isoformat()

                public_key = cert.public_key()
                key_size = getattr(public_key, "key_size", None)
                public_key_type = public_key.__class__.__name__

                sig_alg = None
                try:
                    sig_alg = cert.signature_algorithm_oid._name
                except Exception:
                    try:
                        sig_alg = cert.signature_hash_algorithm.name
                    except Exception:
                        sig_alg = None

                san_dns = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    san_dns = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    san_dns = []

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "expiry": expiry,
                    "signature_algorithm": sig_alg,
                    "key_size": key_size,
                    "public_key_type": public_key_type,
                    "san_dns": san_dns
                }

    except Exception as e:
        logger.warning(f"Certificate scan failed → {host} | {e}")
        return None