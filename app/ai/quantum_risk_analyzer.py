import logging

logger = logging.getLogger("QuantumRiskAnalyzer")


# ---------------------------------------
# Known Post-Quantum Algorithms
# ---------------------------------------

PQC_ALGORITHMS = [
    "MLKEM",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "KYBER",
    "KYBER512",
    "KYBER768",
    "KYBER1024",
    "FRODOKEM",
    "BIKE",
    "NTRU",
    "X25519MLKEM",
    "X25519KYBER",
]


# ---------------------------------------
# Classical algorithms broken by quantum
# ---------------------------------------

SHOR_BREAKABLE = [
    "RSA",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "DSA",
    "SHA256WITHRSA",
    "SHA384WITHRSA",
    "SHA512WITHRSA",
    "RSASSA-PSS",
]


def contains_pqc(text: str) -> bool:
    if not text:
        return False

    text = str(text).upper().strip()

    for algo in PQC_ALGORITHMS:
        if algo in text:
            return True

    return False


def contains_classical(text: str) -> bool:
    if not text:
        return False

    text = str(text).upper().strip()

    for algo in SHOR_BREAKABLE:
        if algo in text:
            return True

    return False


# ---------------------------------------
# Normalize signature algorithm names
# ---------------------------------------

def normalize_signature_algorithm(signature_algorithm: str) -> str:
    if not signature_algorithm:
        return ""

    sig = str(signature_algorithm).upper().strip()
    sig = sig.replace("-", "").replace("_", "").replace(" ", "")

    # RSA variants
    if "SHA256WITHRSAENCRYPTION" in sig or "SHA256WITHRSA" in sig:
        return "SHA256WITHRSA"
    if "SHA384WITHRSAENCRYPTION" in sig or "SHA384WITHRSA" in sig:
        return "SHA384WITHRSA"
    if "SHA512WITHRSAENCRYPTION" in sig or "SHA512WITHRSA" in sig:
        return "SHA512WITHRSA"
    if "RSAPSS" in sig or "RSASSAPSS" in sig:
        return "RSASSA-PSS"

    # ECDSA variants
    if "ECDSA" in sig and "SHA256" in sig:
        return "SHA256WITHECDSA"
    if "ECDSA" in sig and "SHA384" in sig:
        return "SHA384WITHECDSA"
    if "ECDSA" in sig and "SHA512" in sig:
        return "SHA512WITHECDSA"
    if "ECDSA" in sig:
        return "ECDSA"

    # DSA variants
    if "DSA" in sig:
        return "DSA"

    return sig


# ---------------------------------------
# MAIN ANALYZER
# ---------------------------------------

def analyze_quantum_risk(cbom):
    signature_algorithm = normalize_signature_algorithm(
        cbom.get("signature_algorithm")
    )
    cipher = str(cbom.get("cipher_suite") or "").upper().strip()
    key_exchange = str(cbom.get("key_exchange") or "").upper().strip()
    tls_version = str(cbom.get("tls_version") or "").upper().strip()
    key_size = cbom.get("key_size")

    # -----------------------------------
    # 1️⃣ TLS VERSION CHECK
    # -----------------------------------

    if tls_version in ["TLSV1", "TLS1.0", "TLSV1.0", "TLSV1.1", "TLS1.1"]:
        return "CRITICAL"

    # Keep note of TLS 1.2 if needed later
    tls_is_legacy = tls_version in ["TLSV1.2", "TLS1.2"]

    # -----------------------------------
    # 2️⃣ POST-QUANTUM DETECTION
    # -----------------------------------

    pqc_detected = (
        contains_pqc(cipher)
        or contains_pqc(key_exchange)
        or contains_pqc(signature_algorithm)
    )

    classical_detected = (
        contains_classical(cipher)
        or contains_classical(key_exchange)
        or contains_classical(signature_algorithm)
    )

    combined_text = f"{cipher} {key_exchange} {signature_algorithm}"

    # -----------------------------------
    # 3️⃣ HYBRID PQC (Best case)
    # -----------------------------------

    if pqc_detected and classical_detected:
        logger.info("Hybrid Post-Quantum TLS detected")
        return "HYBRID_POST_QUANTUM"

    # Explicit hybrid groups like X25519+MLKEM / X25519+KYBER
    if (
        ("MLKEM" in key_exchange or "KYBER" in key_exchange)
        and "X25519" in key_exchange
    ):
        logger.info("Hybrid PQC key exchange detected")
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
        # RSA cases
        if "RSA" in combined_text or "RSASSA-PSS" in combined_text:
            if isinstance(key_size, int):
                if key_size < 2048:
                    return "CRITICAL"
                return "NOT_QUANTUM_SAFE"

            return "NOT_QUANTUM_SAFE"

        # ECC / DSA cases also quantum vulnerable
        if any(algo in combined_text for algo in ["ECDSA", "ECDH", "ECDHE", "DSA"]):
            return "NOT_QUANTUM_SAFE"

    # -----------------------------------
    # 6️⃣ Legacy TLS fallback
    # -----------------------------------

    if tls_is_legacy:
        return "NOT_QUANTUM_SAFE"

    # -----------------------------------
    # 7️⃣ UNKNOWN CASE
    # -----------------------------------

    return "UNKNOWN"