import logging

logger = logging.getLogger("AttackGraphBuilder")


def build_attack_paths(asset: str, features: dict):

    """
    Builds structured attack paths based on detected cryptography.

    Returns:
        list of dicts:
        [
            {
                "path": ["example.com", "RSA", "Shor Attack"],
                "risk": "HIGH",
                "description": "RSA vulnerable to Shor's algorithm"
            }
        ]
    """

    paths = []

    if not asset:
        return paths

    signature = (features.get("signature_algorithm") or "").upper()
    cipher = (features.get("cipher") or "").upper()
    key_exchange = (features.get("key_exchange") or "").upper()
    tls_version = (features.get("tls_version") or "").upper()
    key_size = features.get("key_size")

    # -----------------------------------------
    # 1️⃣ RSA / ECC → Shor Attack
    # -----------------------------------------
    if "RSA" in signature or "RSA" in cipher:

        risk = "HIGH"

        if key_size:
            if key_size >= 4096:
                risk = "MEDIUM"
            elif key_size < 2048:
                risk = "CRITICAL"

        paths.append({
            "path": [asset, "RSA", "Shor Attack"],
            "risk": risk,
            "description": "RSA can be broken using Shor's algorithm on a quantum computer"
        })

    if "ECDSA" in signature or "ECDHE" in key_exchange:

        paths.append({
            "path": [asset, "ECC", "Shor Attack"],
            "risk": "HIGH",
            "description": "Elliptic Curve cryptography is vulnerable to Shor's algorithm"
        })

    # -----------------------------------------
    # 2️⃣ AES → Grover Attack
    # -----------------------------------------
    if "AES128" in cipher:

        paths.append({
            "path": [asset, "AES128", "Grover Attack"],
            "risk": "MEDIUM",
            "description": "Grover's algorithm reduces AES128 security to 64-bit"
        })

    elif "AES256" in cipher:

        paths.append({
            "path": [asset, "AES256", "Grover Attack"],
            "risk": "LOW",
            "description": "AES256 remains relatively secure against Grover's algorithm"
        })

    # -----------------------------------------
    # 3️⃣ TLS Downgrade Attack
    # -----------------------------------------
    if tls_version in ["TLS1.0", "TLS1.1"]:

        paths.append({
            "path": [asset, tls_version, "Downgrade Attack"],
            "risk": "CRITICAL",
            "description": "Outdated TLS allows downgrade attacks"
        })

    elif tls_version == "TLS1.2":

        paths.append({
            "path": [asset, "TLS1.2", "Downgrade Attack"],
            "risk": "MEDIUM",
            "description": "TLS1.2 may allow downgrade or weaker cipher negotiation"
        })

    # -----------------------------------------
    # 4️⃣ Harvest Now Decrypt Later (HNDL)
    # -----------------------------------------
    if "RSA" in key_exchange:

        paths.append({
            "path": [asset, "RSA Key Exchange", "HNDL Attack"],
            "risk": "CRITICAL",
            "description": "Traffic can be recorded and decrypted later using quantum computers"
        })

    elif "ECDHE" in key_exchange:

        paths.append({
            "path": [asset, "ECDHE", "HNDL Attack"],
            "risk": "MEDIUM",
            "description": "Forward secrecy reduces HNDL risk but still vulnerable in quantum era"
        })

    # -----------------------------------------
    # 5️⃣ PQC Detection (Safe Path)
    # -----------------------------------------
    pqc_keywords = ["KYBER", "MLKEM", "FRODOKEM", "NTRU"]

    for algo in pqc_keywords:
        if algo in cipher or algo in key_exchange or algo in signature:

            paths.append({
                "path": [asset, algo, "Post-Quantum Secure"],
                "risk": "LOW",
                "description": f"{algo} is resistant to quantum attacks"
            })

            break

    # -----------------------------------------
    # 6️⃣ No Attack Detected
    # -----------------------------------------
    if not paths:

        paths.append({
            "path": [asset, "UNKNOWN", "No Known Attack"],
            "risk": "UNKNOWN",
            "description": "No known quantum attack detected"
        })

    logger.info(f"Attack paths generated → {asset}")

    return paths