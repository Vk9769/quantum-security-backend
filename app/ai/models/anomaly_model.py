import logging
from datetime import datetime

logger = logging.getLogger("AnomalyModel")


class AnomalyModel:
    """
    Detect anomalies in TLS + crypto configuration.

    This is a hybrid model:
    - Rule-based (current)
    - ML-ready (future extension)

    Output format is structured for:
    ✔ Kafka events
    ✔ Dashboard UI
    ✔ AI SOC reasoning
    """

    def detect(self, features: dict):

        anomalies = []

        try:
            # -----------------------------------
            # Extract values safely
            # -----------------------------------
            tls_version = (features.get("tls_version") or "").upper()
            cipher_strength = (features.get("cipher_strength") or "").upper()
            key_size = features.get("key_size")
            forward_secrecy = features.get("forward_secrecy")
            pqc_support = features.get("pqc_support")
            classical_crypto = features.get("classical_crypto")

            # -----------------------------------
            # 1️⃣ Deprecated TLS
            # -----------------------------------
            if tls_version in ["TLS1.0", "TLS1.1"]:
                anomalies.append({
                    "type": "tls",
                    "severity": "CRITICAL",
                    "issue": "Deprecated TLS version",
                    "value": tls_version,
                    "description": "Outdated TLS version vulnerable to known attacks"
                })

            # -----------------------------------
            # 2️⃣ Weak Cipher
            # -----------------------------------
            if cipher_strength == "WEAK":
                anomalies.append({
                    "type": "cipher",
                    "severity": "HIGH",
                    "issue": "Weak cipher detected",
                    "value": cipher_strength,
                    "description": "Weak encryption algorithm (RC4/3DES)"
                })

            # -----------------------------------
            # 3️⃣ Weak Key Size
            # -----------------------------------
            if key_size:
                try:
                    key_size = int(key_size)

                    if key_size < 2048:
                        anomalies.append({
                            "type": "crypto",
                            "severity": "CRITICAL",
                            "issue": "Weak key size",
                            "value": key_size,
                            "description": "Key size below secure threshold"
                        })

                    elif key_size < 3072:
                        anomalies.append({
                            "type": "crypto",
                            "severity": "MEDIUM",
                            "issue": "Key size not future-proof",
                            "value": key_size,
                            "description": "Key may be vulnerable in future (quantum risk)"
                        })

                except Exception:
                    pass

            # -----------------------------------
            # 4️⃣ No Forward Secrecy
            # -----------------------------------
            if forward_secrecy is False:
                anomalies.append({
                    "type": "tls_security",
                    "severity": "HIGH",
                    "issue": "No Forward Secrecy",
                    "value": "Disabled",
                    "description": "Susceptible to Harvest Now Decrypt Later attacks"
                })

            # -----------------------------------
            # 5️⃣ Classical Crypto Detected
            # -----------------------------------
            if classical_crypto:
                anomalies.append({
                    "type": "quantum_risk",
                    "severity": "HIGH",
                    "issue": "Classical cryptography in use",
                    "value": "RSA/ECC",
                    "description": "Vulnerable to Shor's algorithm"
                })

            # -----------------------------------
            # 6️⃣ Missing PQC Support
            # -----------------------------------
            if not pqc_support:
                anomalies.append({
                    "type": "pqc",
                    "severity": "MEDIUM",
                    "issue": "No Post-Quantum Cryptography",
                    "value": "Not Detected",
                    "description": "System not resistant to quantum attacks"
                })

            # -----------------------------------
            # 7️⃣ No anomalies fallback
            # -----------------------------------
            if not anomalies:
                anomalies.append({
                    "type": "status",
                    "severity": "LOW",
                    "issue": "No anomalies detected",
                    "value": "SAFE",
                    "description": "Configuration appears secure"
                })

            logger.info(f"Anomalies detected → {len(anomalies)}")

            return {
                "timestamp": datetime.utcnow().isoformat(),
                "total_anomalies": len(anomalies),
                "anomalies": anomalies
            }

        except Exception as e:

            logger.error("Anomaly detection failed")
            logger.error(e)

            return {
                "timestamp": datetime.utcnow().isoformat(),
                "total_anomalies": 0,
                "anomalies": [],
                "error": str(e)
            }