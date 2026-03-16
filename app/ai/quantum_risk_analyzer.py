import logging

logger = logging.getLogger("QuantumRiskAnalyzer")


# ---------------------------------------
# Known Post-Quantum Algorithms
# ---------------------------------------

PQC_ALGORITHMS = [
    "MLKEM",
    "KYBER",
    "FRODOKEM",
    "BIKE",
    "NTRU"
]

# ---------------------------------------
# Classical algorithms broken by quantum
# ---------------------------------------

SHOR_BREAKABLE = [
    "RSA",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DSA"
]


def contains_pqc(text: str):

    if not text:
        return False

    text = text.upper()

    for algo in PQC_ALGORITHMS:
        if algo in text:
            return True

    return False


def contains_classical(text: str):

    if not text:
        return False

    text = text.upper()

    for algo in SHOR_BREAKABLE:
        if algo in text:
            return True

    return False


# ---------------------------------------
# MAIN ANALYZER
# ---------------------------------------

def analyze_quantum_risk(cbom):

    signature_algorithm = (cbom.get("signature_algorithm") or "").upper()
    cipher = (cbom.get("cipher_suite") or "").upper()
    key_exchange = (cbom.get("key_exchange") or "").upper()
    tls_version = (cbom.get("tls_version") or "").upper()
    key_size = cbom.get("key_size")

    # -----------------------------------
    # 1️⃣ TLS VERSION CHECK
    # -----------------------------------

    if tls_version in ["TLSV1", "TLSV1.1"]:
        return "CRITICAL"

    if tls_version == "TLSV1.2":
        tls_risk = "WEAK"
    else:
        tls_risk = "GOOD"

    # -----------------------------------
    # 2️⃣ POST-QUANTUM DETECTION
    # -----------------------------------

    pqc_detected = (
        contains_pqc(cipher) or
        contains_pqc(key_exchange) or
        contains_pqc(signature_algorithm)
    )

    classical_detected = (
        contains_classical(cipher) or
        contains_classical(key_exchange) or
        contains_classical(signature_algorithm)
    )

    # -----------------------------------
    # 3️⃣ HYBRID PQC (Best case)
    # -----------------------------------

    if pqc_detected and classical_detected:

        logger.info("Hybrid Post-Quantum TLS detected")

        return "HYBRID_POST_QUANTUM"

    # -----------------------------------
    # 4️⃣ FULL PQC
    # -----------------------------------

    if pqc_detected and not classical_detected:

        logger.info("Pure Post-Quantum cryptography detected")

        return "POST_QUANTUM_SAFE"

    # -----------------------------------
    # 5️⃣ CLASSICAL CRYPTO (Broken by Shor)
    # -----------------------------------

    if classical_detected:

        if "RSA" in signature_algorithm and key_size:

            if key_size < 2048:
                return "CRITICAL"

            if key_size < 3072:
                return "NOT_QUANTUM_SAFE"

        return "NOT_QUANTUM_SAFE"

    # -----------------------------------
    # 6️⃣ UNKNOWN CASE
    # -----------------------------------

    return "UNKNOWN"