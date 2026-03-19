import logging
from datetime import datetime

logger = logging.getLogger("ScanAgent")


class ScanAgent:
    """
    ScanAgent decides what actions should be performed next
    based on extracted security features.

    This acts like a SOC decision engine.
    """

    def __init__(self):
        self.agent_name = "ScanAgent"

    # -----------------------------------
    # Main Decision Function
    # -----------------------------------
    def decide_next_steps(self, features: dict) -> list:
        """
        Returns a list of recommended scan actions.

        Example:
        [
            {
                "action": "deep_crypto_scan",
                "priority": "HIGH",
                "reason": "Weak key detected"
            }
        ]
        """

        actions = []

        try:
            if not isinstance(features, dict):
                logger.error("Invalid features input")
                return []

            logger.info(f"🔍 ScanAgent analyzing features → {features}")

            # -----------------------------------
            # Extract features safely
            # -----------------------------------
            weak_key = features.get("weak_key", False)
            medium_key = features.get("medium_key", False)
            classical_crypto = features.get("classical_crypto", False)
            forward_secrecy = features.get("forward_secrecy", True)
            pqc_support = features.get("pqc_support", False)
            weak_tls = features.get("weak_tls", False)

            # -----------------------------------
            # 1️⃣ Deep Crypto Scan
            # -----------------------------------
            if weak_key or classical_crypto:
                actions.append(self._build_action(
                    action="deep_crypto_scan",
                    priority="HIGH",
                    reason="Weak or quantum-vulnerable cryptography detected"
                ))

            elif medium_key:
                actions.append(self._build_action(
                    action="crypto_strengthening_check",
                    priority="MEDIUM",
                    reason="Key size not future-proof"
                ))

            # -----------------------------------
            # 2️⃣ MITM Simulation
            # -----------------------------------
            if not forward_secrecy:
                actions.append(self._build_action(
                    action="mitm_simulation",
                    priority="CRITICAL",
                    reason="No forward secrecy → HNDL risk"
                ))

            # -----------------------------------
            # 3️⃣ PQC Audit
            # -----------------------------------
            if not pqc_support:
                actions.append(self._build_action(
                    action="pqc_audit",
                    priority="HIGH",
                    reason="Post-Quantum cryptography not detected"
                ))

            # -----------------------------------
            # 4️⃣ TLS Hardening Check
            # -----------------------------------
            if weak_tls:
                actions.append(self._build_action(
                    action="tls_hardening",
                    priority="CRITICAL",
                    reason="Deprecated TLS version detected"
                ))

            # -----------------------------------
            # 5️⃣ Cipher Strength Check
            # -----------------------------------
            cipher_strength = features.get("cipher_strength")

            if cipher_strength == "WEAK":
                actions.append(self._build_action(
                    action="cipher_upgrade",
                    priority="HIGH",
                    reason="Weak cipher detected (RC4/3DES)"
                ))

            elif cipher_strength == "MEDIUM":
                actions.append(self._build_action(
                    action="cipher_review",
                    priority="MEDIUM",
                    reason="Cipher not optimal for quantum era"
                ))

            # -----------------------------------
            # 6️⃣ Default Safe Case
            # -----------------------------------
            if not actions:
                actions.append(self._build_action(
                    action="monitor_only",
                    priority="LOW",
                    reason="No immediate threats detected"
                ))

            # -----------------------------------
            # Deduplicate Actions
            # -----------------------------------
            actions = self._deduplicate(actions)

            logger.info(f"✅ ScanAgent decisions → {actions}")

            return actions

        except Exception as e:
            logger.error("❌ ScanAgent failed")
            logger.error(e)
            return []

    # -----------------------------------
    # Helper: Build Action Object
    # -----------------------------------
    def _build_action(self, action: str, priority: str, reason: str) -> dict:
        return {
            "action": action,
            "priority": priority,
            "reason": reason,
            "agent": self.agent_name,
            "timestamp": datetime.utcnow().isoformat()
        }

    # -----------------------------------
    # Helper: Remove duplicate actions
    # -----------------------------------
    def _deduplicate(self, actions: list) -> list:

        seen = set()
        unique_actions = []

        for a in actions:
            key = a["action"]

            if key not in seen:
                seen.add(key)
                unique_actions.append(a)

        return unique_actions