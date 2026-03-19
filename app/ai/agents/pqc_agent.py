import logging

logger = logging.getLogger("PQCAgent")


class PQCAgent:

    def __init__(self):
        pass

    # -----------------------------------
    # Normalize helper
    # -----------------------------------
    def _normalize(self, value):
        if not value:
            return ""
        return str(value).upper()

    # -----------------------------------
    # Detect PQC presence
    # -----------------------------------
    def _has_pqc(self, text):
        pqc_keywords = ["KYBER", "MLKEM", "FRODOKEM", "BIKE", "NTRU"]
        return any(k in text for k in pqc_keywords)

    # -----------------------------------
    # Detect classical crypto
    # -----------------------------------
    def _has_classical(self, text):
        classical = ["RSA", "ECDSA", "ECDH", "ECDHE", "DSA"]
        return any(c in text for c in classical)

    # -----------------------------------
    # Main migration planner
    # -----------------------------------
    def plan_migration(self, features):

        try:
            signature = self._normalize(features.get("signature_algorithm"))
            key_exchange = self._normalize(features.get("key_exchange"))
            cipher = self._normalize(features.get("cipher"))
            tls_version = self._normalize(features.get("tls_version"))
            key_size = features.get("key_size")

            logger.info(f"PQC Agent Input → {features}")

            plan = []

            # -----------------------------------
            # 1️⃣ Signature Migration
            # -----------------------------------
            if "RSA" in signature:

                if key_size and key_size < 3072:
                    plan.append({
                        "priority": "HIGH",
                        "action": "Replace RSA with Dilithium",
                        "reason": "RSA vulnerable to Shor’s algorithm"
                    })

                else:
                    plan.append({
                        "priority": "MEDIUM",
                        "action": "Migrate RSA → Dilithium (PQC signature)",
                        "reason": "Future quantum threat"
                    })

            elif "ECDSA" in signature:

                plan.append({
                    "priority": "HIGH",
                    "action": "Replace ECDSA with Dilithium or Falcon",
                    "reason": "ECC broken by Shor’s algorithm"
                })

            # -----------------------------------
            # 2️⃣ Key Exchange Migration
            # -----------------------------------
            if "ECDHE" in key_exchange or "ECDH" in key_exchange:

                plan.append({
                    "priority": "HIGH",
                    "action": "Replace ECDHE with Kyber768",
                    "reason": "ECC key exchange vulnerable to quantum attacks"
                })

            if "RSA" in key_exchange:

                plan.append({
                    "priority": "CRITICAL",
                    "action": "Remove RSA key exchange immediately",
                    "reason": "No forward secrecy + quantum breakable"
                })

            # -----------------------------------
            # 3️⃣ Cipher Upgrade
            # -----------------------------------
            if "AES_128" in cipher or "AES128" in cipher:

                plan.append({
                    "priority": "MEDIUM",
                    "action": "Upgrade AES-128 → AES-256",
                    "reason": "Grover reduces effective security"
                })

            if "3DES" in cipher or "RC4" in cipher:

                plan.append({
                    "priority": "CRITICAL",
                    "action": "Remove weak cipher (3DES/RC4)",
                    "reason": "Broken classical encryption"
                })

            # -----------------------------------
            # 4️⃣ TLS Version Upgrade
            # -----------------------------------
            if tls_version in ["TLS1.0", "TLS1.1"]:

                plan.append({
                    "priority": "CRITICAL",
                    "action": "Upgrade to TLS 1.3 immediately",
                    "reason": "Deprecated and vulnerable protocol"
                })

            elif tls_version == "TLS1.2":

                plan.append({
                    "priority": "HIGH",
                    "action": "Upgrade to TLS 1.3",
                    "reason": "Better security and PQC readiness"
                })

            # -----------------------------------
            # 5️⃣ Key Size Check
            # -----------------------------------
            if key_size:
                try:
                    key_size = int(key_size)

                    if key_size < 2048:
                        plan.append({
                            "priority": "CRITICAL",
                            "action": "Increase key size ≥ 3072 or migrate to PQC",
                            "reason": "Weak key size"
                        })

                    elif key_size < 3072:
                        plan.append({
                            "priority": "HIGH",
                            "action": "Upgrade key size or move to PQC",
                            "reason": "Not future-proof"
                        })

                except Exception:
                    pass

            # -----------------------------------
            # 6️⃣ PQC Detection (Already Safe)
            # -----------------------------------
            combined = f"{cipher} {key_exchange} {signature}"

            pqc_detected = self._has_pqc(combined)
            classical_detected = self._has_classical(combined)

            if pqc_detected and classical_detected:

                plan.append({
                    "priority": "LOW",
                    "action": "Maintain Hybrid PQC deployment",
                    "reason": "Best practice for gradual migration"
                })

            elif pqc_detected and not classical_detected:

                plan.append({
                    "priority": "LOW",
                    "action": "System is fully PQC-secured",
                    "reason": "Quantum-resistant cryptography detected"
                })

            else:

                plan.append({
                    "priority": "HIGH",
                    "action": "Adopt Hybrid TLS (X25519 + MLKEM)",
                    "reason": "No PQC detected"
                })

            # -----------------------------------
            # 7️⃣ Deduplicate recommendations
            # -----------------------------------
            unique_plan = []
            seen = set()

            for item in plan:
                key = item["action"]
                if key not in seen:
                    unique_plan.append(item)
                    seen.add(key)

            logger.info(f"PQC Migration Plan → {unique_plan}")

            return unique_plan

        except Exception as e:

            logger.error("PQCAgent failed")
            logger.error(e)

            return [{
                "priority": "UNKNOWN",
                "action": "Unable to generate PQC plan",
                "reason": str(e)
            }]