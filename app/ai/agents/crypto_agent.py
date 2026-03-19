import logging

logger = logging.getLogger("CryptoAgent")


class CryptoAgent:
    """
    Advanced Cryptography Analysis Agent

    Responsibilities:
    - Detect weak / classical crypto
    - Identify quantum vulnerabilities
    - Provide structured security issues
    - Recommend fixes
    """

    def analyze(self, features: dict):

        results = []

        try:
            # -----------------------------------
            # Normalize Inputs
            # -----------------------------------
            signature = (features.get("signature_algorithm") or "").upper()
            cipher = (features.get("cipher") or "").upper()
            key_exchange = (features.get("key_exchange") or "").upper()
            key_size = features.get("key_size")
            forward_secrecy = features.get("forward_secrecy")

            # -----------------------------------
            # 1️⃣ Classical Crypto Detection
            # -----------------------------------
            if features.get("classical_crypto"):

                results.append({
                    "type": "quantum_vulnerability",
                    "issue": "Classical cryptography detected",
                    "risk": "CRITICAL",
                    "impact": "Vulnerable to Shor's algorithm (quantum attack)",
                    "affected_component": signature or key_exchange,
                    "recommendation": "Migrate to Post-Quantum Cryptography (Dilithium / Kyber)"
                })

            # -----------------------------------
            # 2️⃣ Weak Key Size
            # -----------------------------------
            if key_size:

                try:
                    key_size = int(key_size)

                    if key_size < 2048:
                        results.append({
                            "type": "weak_crypto",
                            "issue": "Weak key size",
                            "risk": "CRITICAL",
                            "impact": "Easily breakable even without quantum computers",
                            "key_size": key_size,
                            "recommendation": "Upgrade to minimum 3072-bit or PQC"
                        })

                    elif key_size < 3072:
                        results.append({
                            "type": "weak_crypto",
                            "issue": "Key not future-proof",
                            "risk": "HIGH",
                            "impact": "Not secure against future quantum attacks",
                            "key_size": key_size,
                            "recommendation": "Upgrade to PQC or >= 3072-bit"
                        })

                except Exception:
                    logger.warning("Invalid key size format")

            # -----------------------------------
            # 3️⃣ Forward Secrecy Check (HNDL Attack)
            # -----------------------------------
            if not forward_secrecy:

                results.append({
                    "type": "crypto_weakness",
                    "issue": "No Forward Secrecy",
                    "risk": "CRITICAL",
                    "attack": "Harvest Now Decrypt Later (HNDL)",
                    "impact": "Traffic can be recorded and decrypted later using quantum computers",
                    "recommendation": "Use ECDHE or PQC key exchange (Kyber)"
                })

            # -----------------------------------
            # 4️⃣ Weak Cipher Detection
            # -----------------------------------
            if any(x in cipher for x in ["RC4", "3DES"]):

                results.append({
                    "type": "weak_cipher",
                    "issue": "Deprecated cipher detected",
                    "risk": "HIGH",
                    "cipher": cipher,
                    "recommendation": "Use AES-256-GCM or CHACHA20"
                })

            # -----------------------------------
            # 5️⃣ Missing PQC Support
            # -----------------------------------
            if not features.get("pqc_support"):

                results.append({
                    "type": "pqc_gap",
                    "issue": "No Post-Quantum Cryptography",
                    "risk": "HIGH",
                    "impact": "System not secure against quantum adversaries",
                    "recommendation": "Adopt hybrid PQC TLS (X25519 + MLKEM)"
                })

            # -----------------------------------
            # 6️⃣ Safe Configuration (Optional)
            # -----------------------------------
            if not results:

                results.append({
                    "type": "secure",
                    "issue": "Configuration appears secure",
                    "risk": "LOW",
                    "recommendation": "Continue monitoring and apply updates"
                })

        except Exception as e:
            logger.error("CryptoAgent failed")
            logger.error(e)

            return [{
                "type": "error",
                "issue": "Crypto analysis failed",
                "risk": "UNKNOWN"
            }]

        logger.info(f"Crypto analysis completed → {results}")

        return results