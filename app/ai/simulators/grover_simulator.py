import logging

logger = logging.getLogger("GroverSimulator")


def simulate_grover(cipher: str) -> dict:
    """
    Simulate Grover's Algorithm impact on symmetric encryption.

    Grover reduces effective key strength by half:
    - AES-128 → 64-bit security
    - AES-256 → 128-bit security

    Args:
        cipher (str): TLS cipher suite (e.g. TLS_AES_128_GCM_SHA256)

    Returns:
        dict: Simulation result
    """

    if not cipher:
        logger.warning("No cipher provided for Grover simulation")
        return {
            "attack": "Grover",
            "algorithm_type": "symmetric",
            "original_security": None,
            "effective_security": None,
            "risk": "UNKNOWN"
        }

    cipher = cipher.upper()

    logger.info(f"Running Grover simulation → {cipher}")

    # -----------------------------------
    # AES-128
    # -----------------------------------
    if "AES_128" in cipher or "AES128" in cipher:
        return {
            "attack": "Grover",
            "algorithm": "AES-128",
            "algorithm_type": "symmetric",
            "original_security": "128-bit",
            "effective_security": "64-bit",
            "risk": "MEDIUM",
            "quantum_impact": "Key search space reduced using Grover's algorithm"
        }

    # -----------------------------------
    # AES-256
    # -----------------------------------
    if "AES_256" in cipher or "AES256" in cipher:
        return {
            "attack": "Grover",
            "algorithm": "AES-256",
            "algorithm_type": "symmetric",
            "original_security": "256-bit",
            "effective_security": "128-bit",
            "risk": "LOW",
            "quantum_impact": "Still considered quantum-resistant with larger key size"
        }

    # -----------------------------------
    # CHACHA20
    # -----------------------------------
    if "CHACHA20" in cipher:
        return {
            "attack": "Grover",
            "algorithm": "CHACHA20",
            "algorithm_type": "symmetric",
            "original_security": "256-bit",
            "effective_security": "128-bit",
            "risk": "LOW",
            "quantum_impact": "Reduced security but still acceptable"
        }

    # -----------------------------------
    # Unknown symmetric cipher
    # -----------------------------------
    logger.warning(f"Unknown cipher for Grover simulation → {cipher}")

    return {
        "attack": "Grover",
        "algorithm": cipher,
        "algorithm_type": "symmetric",
        "original_security": "UNKNOWN",
        "effective_security": "UNKNOWN",
        "risk": "UNKNOWN",
        "quantum_impact": "Unable to determine impact"
    }