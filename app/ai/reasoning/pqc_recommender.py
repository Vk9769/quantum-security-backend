import logging

logger = logging.getLogger("PQCRecommender")


def normalize(value):
    """
    Normalize input values safely
    """
    if not value:
        return ""
    return str(value).upper()


def recommend_pqc(features):
    """
    Generate Post-Quantum Cryptography (PQC) recommendations
    based on detected TLS, cipher, and certificate configuration.
    """

    recommendations = []

    # Normalize all inputs
    signature = normalize(features.get("signature_algorithm"))
    key_exchange = normalize(features.get("key_exchange"))
    cipher = normalize(features.get("cipher"))
    tls_version = normalize(features.get("tls_version"))
    key_size = features.get("key_size")

    logger.info(f"PQC Recommender Input → {features}")

    # -----------------------------------
    # 1️⃣ Signature Algorithm Checks
    # -----------------------------------
    if "RSA" in signature:
        recommendations.append(
            "Replace RSA with Dilithium (Post-Quantum Signature)"
        )

    elif "ECDSA" in signature:
        recommendations.append(
            "Replace ECDSA with Dilithium or Falcon"
        )

    # -----------------------------------
    # 2️⃣ Key Exchange Checks
    # -----------------------------------
    if "ECDHE" in key_exchange or "ECDH" in key_exchange:
        recommendations.append(
            "Replace ECDHE with Kyber768 (Post-Quantum Key Exchange)"
        )

    if "RSA" in key_exchange:
        recommendations.append(
            "Avoid RSA key exchange, use Kyber or Hybrid PQC TLS"
        )

    # -----------------------------------
    # 3️⃣ Cipher Suite Checks
    # -----------------------------------
    if "AES128" in cipher:
        recommendations.append(
            "Upgrade AES-128 to AES-256 to resist Grover's algorithm"
        )

    if "3DES" in cipher or "RC4" in cipher:
        recommendations.append(
            "Remove weak cipher (3DES/RC4), use AES-256-GCM"
        )

    # -----------------------------------
    # 4️⃣ TLS Version Checks
    # -----------------------------------
    if tls_version in ["TLS1.0", "TLS1.1"]:
        recommendations.append(
            "Upgrade immediately to TLS 1.3 (critical vulnerability)"
        )

    elif tls_version == "TLS1.2":
        recommendations.append(
            "Upgrade to TLS 1.3 for better forward secrecy and PQC readiness"
        )

    # -----------------------------------
    # 5️⃣ Key Size Checks
    # -----------------------------------
    if key_size:
        try:
            key_size = int(key_size)

            if key_size < 2048:
                recommendations.append(
                    "Key size too small → upgrade to minimum 3072-bit or PQC"
                )

            elif key_size < 3072:
                recommendations.append(
                    "Key size not future-proof → consider PQC migration"
                )

        except Exception:
            pass

    # -----------------------------------
    # 6️⃣ PQC Detection (Already Safe)
    # -----------------------------------
    pqc_keywords = ["KYBER", "MLKEM", "FRODOKEM", "NTRU", "BIKE"]

    if any(k in key_exchange for k in pqc_keywords) or \
       any(k in cipher for k in pqc_keywords):

        recommendations.append(
            "Post-Quantum cryptography detected → maintain hybrid deployment"
        )

    # -----------------------------------
    # 7️⃣ Fallback (No Issues)
    # -----------------------------------
    if not recommendations:
        recommendations.append("Configuration appears quantum-safe (monitor updates)")

    logger.info(f"PQC Recommendations → {recommendations}")

    return recommendations