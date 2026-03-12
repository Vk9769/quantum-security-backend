import logging

logger = logging.getLogger("QuantumRiskAnalyzer")


def analyze_quantum_risk(cbom):

    signature_algorithm = cbom.get("signature_algorithm") or ""
    cipher = cbom.get("cipher_suite") or ""
    tls_version = cbom.get("tls_version") or ""
    key_size = cbom.get("key_size")

    # ------------------------------------
    # Algorithms broken by Shor's algorithm
    # ------------------------------------

    if "RSA" in signature_algorithm:
        return "NOT_QUANTUM_SAFE"

    if "ECDSA" in signature_algorithm:
        return "NOT_QUANTUM_SAFE"

    if "ECDHE" in cipher:
        return "NOT_QUANTUM_SAFE"

    if "ECDH" in cipher:
        return "NOT_QUANTUM_SAFE"

    # ------------------------------------
    # Weak TLS versions
    # ------------------------------------

    if tls_version in ["TLSv1", "TLSv1.1"]:
        return "CRITICAL"

    # ------------------------------------
    # Unknown / cannot determine
    # ------------------------------------

    return "UNKNOWN"