import logging

logger = logging.getLogger("MITMSimulator")


def normalize(value):
    if not value:
        return ""
    return str(value).upper()


def simulate_mitm(features: dict) -> dict:
    """
    Advanced MITM Attack Simulation

    Evaluates:
    - Forward Secrecy
    - TLS Version
    - Cipher Strength
    - Key Exchange
    - PQC Presence

    Returns:
        dict: Detailed MITM attack feasibility report
    """

    try:
        # -----------------------------------
        # Normalize Inputs
        # -----------------------------------
        tls_version = normalize(features.get("tls_version"))
        cipher = normalize(features.get("cipher"))
        key_exchange = normalize(features.get("key_exchange"))
        forward_secrecy = features.get("forward_secrecy", False)
        pqc_support = features.get("pqc_support", False)

        logger.info(f"Running MITM simulation → TLS={tls_version}, Cipher={cipher}")

        # -----------------------------------
        # Risk Factors
        # -----------------------------------
        reasons = []
        risk_score = 0

        # 1️⃣ Forward Secrecy Check (MOST IMPORTANT)
        if not forward_secrecy:
            risk_score += 40
            reasons.append("No forward secrecy → session keys can be decrypted (HNDL risk)")

        # 2️⃣ TLS Version Weakness
        if tls_version in ["TLS1.0", "TLS1.1"]:
            risk_score += 40
            reasons.append("Deprecated TLS version allows downgrade and interception")

        elif tls_version == "TLS1.2":
            risk_score += 15
            reasons.append("TLS 1.2 may allow downgrade attacks")

        elif tls_version == "TLS1.3":
            reasons.append("TLS 1.3 resists downgrade attacks")

        # 3️⃣ Weak Cipher Detection
        if "RC4" in cipher or "3DES" in cipher:
            risk_score += 30
            reasons.append("Weak cipher detected (RC4/3DES)")

        # 4️⃣ RSA Key Exchange (HNDL)
        if "RSA" in key_exchange:
            risk_score += 30
            reasons.append("RSA key exchange vulnerable to HNDL (store now decrypt later)")

        # 5️⃣ PQC Presence (reduces risk)
        if pqc_support:
            risk_score -= 20
            reasons.append("Post-Quantum cryptography reduces MITM feasibility")

        # -----------------------------------
        # Final Risk Level
        # -----------------------------------
        if risk_score >= 70:
            risk = "CRITICAL"
            success = "HIGH"
        elif risk_score >= 40:
            risk = "HIGH"
            success = "MEDIUM"
        elif risk_score >= 20:
            risk = "MEDIUM"
            success = "LOW"
        else:
            risk = "LOW"
            success = "VERY_LOW"

        # -----------------------------------
        # Attack Scenario Simulation
        # -----------------------------------
        scenario = []

        if not forward_secrecy:
            scenario.append("Attacker captures encrypted traffic")
            scenario.append("Stores traffic for future decryption")
            scenario.append("Quantum computer breaks key (Shor)")
            scenario.append("Decrypts past sessions (HNDL attack)")

        if tls_version in ["TLS1.0", "TLS1.1", "TLS1.2"]:
            scenario.append("Attacker forces protocol downgrade")
            scenario.append("Intercepts weak TLS handshake")

        if "RSA" in key_exchange:
            scenario.append("Attacker exploits RSA key exchange weakness")

        if pqc_support:
            scenario.append("Hybrid PQC reduces attack success probability")

        # -----------------------------------
        # Recommended Actions
        # -----------------------------------
        recommendations = []

        if not forward_secrecy:
            recommendations.append("Enable ECDHE or PQC-based key exchange")

        if tls_version in ["TLS1.0", "TLS1.1"]:
            recommendations.append("Disable legacy TLS versions")

        if tls_version == "TLS1.2":
            recommendations.append("Upgrade to TLS 1.3")

        if "RSA" in key_exchange:
            recommendations.append("Replace RSA key exchange with Kyber")

        if not pqc_support:
            recommendations.append("Adopt hybrid PQC TLS (X25519 + MLKEM)")

        if not recommendations:
            recommendations.append("Configuration is secure against MITM")

        # -----------------------------------
        # Final Result
        # -----------------------------------
        return {
            "attack": "MITM",
            "category": "network_attack",
            "risk": risk,
            "success_probability": success,
            "risk_score": risk_score,
            "reasons": reasons,
            "attack_scenario": scenario,
            "recommendations": recommendations
        }

    except Exception as e:
        logger.error("MITM simulation failed")
        logger.error(e)

        return {
            "attack": "MITM",
            "risk": "UNKNOWN",
            "success_probability": "UNKNOWN",
            "error": str(e)
        }