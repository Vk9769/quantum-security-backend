import re


# -----------------------------------------
# Helpers
# -----------------------------------------

def normalize_tls_version(version):
    if not version:
        return "UNKNOWN"

    version = str(version).upper().replace(".", "")

    if "TLSV13" in version or "TLS1_3" in version:
        return "TLS1.3"
    if "TLSV12" in version or "TLS1_2" in version:
        return "TLS1.2"
    if "TLSV11" in version:
        return "TLS1.1"
    if "TLSV1" in version:
        return "TLS1.0"

    return version


def detect_forward_secrecy(cipher):
    if not cipher:
        return False

    cipher = cipher.upper()

    return any(x in cipher for x in ["DHE", "ECDHE"])


def detect_pqc(cipher, key_exchange, signature):
    pqc_keywords = ["KYBER", "MLKEM", "FRODOKEM", "BIKE", "NTRU"]

    text = f"{cipher} {key_exchange} {signature}".upper()

    return any(k in text for k in pqc_keywords)


def detect_classical(signature, key_exchange):
    classical = ["RSA", "ECDSA", "ECDH", "DSA"]

    text = f"{signature} {key_exchange}".upper()

    return any(c in text for c in classical)


def normalize_key_size(key_size):
    try:
        return int(key_size)
    except:
        return None


def extract_cipher_strength(cipher):
    if not cipher:
        return "UNKNOWN"

    cipher = cipher.upper()

    if "AES_256" in cipher:
        return "STRONG"
    if "AES_128" in cipher:
        return "MEDIUM"
    if "3DES" in cipher or "RC4" in cipher:
        return "WEAK"

    return "UNKNOWN"


# -----------------------------------------
# MAIN FEATURE EXTRACTION
# -----------------------------------------

def extract_features(tls_event, cert_event=None):

    cipher = tls_event.get("cipher_suite")
    key_exchange = tls_event.get("key_exchange")
    signature = tls_event.get("signature_algorithm")
    key_size = tls_event.get("key_size")

    # fallback from certificate event if missing
    if cert_event:
        signature = signature or cert_event.get("signature_algorithm")
        key_size = key_size or cert_event.get("key_size")

    tls_version = normalize_tls_version(
        tls_event.get("tls_version")
    )

    key_size = normalize_key_size(key_size)

    forward_secrecy = detect_forward_secrecy(cipher)

    pqc_support = detect_pqc(cipher, key_exchange, signature)

    classical_crypto = detect_classical(signature, key_exchange)

    cipher_strength = extract_cipher_strength(cipher)

    # -----------------------------------------
    # Derived Risk Signals (VERY IMPORTANT)
    # -----------------------------------------

    weak_tls = tls_version in ["TLS1.0", "TLS1.1"]

    weak_key = key_size is not None and key_size < 2048

    medium_key = key_size is not None and 2048 <= key_size < 3072

    # -----------------------------------------
    # Final Feature Object
    # -----------------------------------------

    features = {

        # Basic
        "tls_version": tls_version,
        "cipher": cipher,
        "key_exchange": key_exchange,
        "signature_algorithm": signature,
        "key_size": key_size,

        # Derived
        "forward_secrecy": forward_secrecy,
        "pqc_support": pqc_support,
        "classical_crypto": classical_crypto,
        "cipher_strength": cipher_strength,

        # Risk indicators
        "weak_tls": weak_tls,
        "weak_key": weak_key,
        "medium_key": medium_key
    }

    return features