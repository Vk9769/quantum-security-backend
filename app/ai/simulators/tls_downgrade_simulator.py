import logging

logger = logging.getLogger("TLSDowngradeSimulator")


def normalize_tls_version(version):
    """
    Normalize TLS version strings to standard format.
    Examples:
    TLSv1.2 → TLS1.2
    tls1_3 → TLS1.3
    """

    if not version:
        return "UNKNOWN"

    version = version.upper().replace("_", ".").replace("V", "")

    if "1.0" in version:
        return "TLS1.0"
    elif "1.1" in version:
        return "TLS1.1"
    elif "1.2" in version:
        return "TLS1.2"
    elif "1.3" in version:
        return "TLS1.3"

    return "UNKNOWN"


def simulate_tls_downgrade(tls_version):
    """
    Simulate TLS downgrade attack feasibility.

    Returns:
    {
        attack: "TLS_Downgrade",
        risk: "HIGH/MEDIUM/LOW/UNKNOWN",
        description: "...",
        downgrade_possible: True/False,
        recommended_action: "..."
    }
    """

    normalized = normalize_tls_version(tls_version)

    logger.info(f"Simulating TLS downgrade → {normalized}")

    # -----------------------------
    # HIGH RISK (Legacy TLS)
    # -----------------------------
    if normalized in ["TLS1.0", "TLS1.1"]:

        return {
            "attack": "TLS_Downgrade",
            "tls_version": normalized,
            "risk": "HIGH",
            "downgrade_possible": True,
            "description": "Server supports deprecated TLS version. Vulnerable to downgrade and known attacks.",
            "recommended_action": "Disable TLS 1.0 and 1.1. Enforce TLS 1.3 only."
        }

    # -----------------------------
    # MEDIUM RISK (TLS 1.2)
    # -----------------------------
    if normalized == "TLS1.2":

        return {
            "attack": "TLS_Downgrade",
            "tls_version": normalized,
            "risk": "MEDIUM",
            "downgrade_possible": True,
            "description": "TLS 1.2 may allow downgrade if weaker versions are enabled.",
            "recommended_action": "Prefer TLS 1.3 and disable fallback mechanisms."
        }

    # -----------------------------
    # LOW RISK (TLS 1.3)
    # -----------------------------
    if normalized == "TLS1.3":

        return {
            "attack": "TLS_Downgrade",
            "tls_version": normalized,
            "risk": "LOW",
            "downgrade_possible": False,
            "description": "TLS 1.3 is resistant to downgrade attacks.",
            "recommended_action": "No action needed. Configuration is secure."
        }

    # -----------------------------
    # UNKNOWN
    # -----------------------------
    return {
        "attack": "TLS_Downgrade",
        "tls_version": normalized,
        "risk": "UNKNOWN",
        "downgrade_possible": None,
        "description": "TLS version could not be determined.",
        "recommended_action": "Verify TLS configuration manually."
    }