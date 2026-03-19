import logging

from app.ai.simulators.shor_simulator import simulate_shor_attack
from app.ai.simulators.grover_simulator import simulate_grover
from app.ai.simulators.tls_downgrade_simulator import simulate_tls_downgrade

logger = logging.getLogger("AttackAgent")


# -----------------------------------
# Helper Functions
# -----------------------------------

def is_classical_crypto(signature, key_exchange):
    classical = ["RSA", "ECDSA", "ECDH", "ECDHE", "DSA"]
    text = f"{signature} {key_exchange}".upper()
    return any(c in text for c in classical)


def is_pqc_crypto(cipher, key_exchange, signature):
    pqc = ["KYBER", "MLKEM", "FRODOKEM", "NTRU", "BIKE"]
    text = f"{cipher} {key_exchange} {signature}".upper()
    return any(p in text for p in pqc)


# -----------------------------------
# MAIN AGENT
# -----------------------------------

class AttackAgent:

    def run(self, features: dict):

        results = []

        try:
            # -----------------------------------
            # Normalize Inputs
            # -----------------------------------
            signature = (features.get("signature_algorithm") or "").upper()
            cipher = (features.get("cipher") or "").upper()
            tls_version = (features.get("tls_version") or "").upper()
            key_exchange = (features.get("key_exchange") or "").upper()
            key_size = features.get("key_size")

            logger.info(f"Running attack simulation → {features}")

            # -----------------------------------
            # 1️⃣ Shor Attack (Quantum - Asymmetric)
            # -----------------------------------
            if is_classical_crypto(signature, key_exchange):

                shor_result = simulate_shor_attack(key_size)

                results.append({
                    "type": "quantum_attack",
                    "name": "Shor",
                    "category": "asymmetric_crypto",
                    "target": signature or key_exchange,
                    "details": shor_result
                })

            # -----------------------------------
            # 2️⃣ Grover Attack (Quantum - Symmetric)
            # -----------------------------------
            if any(x in cipher for x in ["AES", "CHACHA20"]):

                grover_result = simulate_grover(cipher)

                results.append({
                    "type": "quantum_attack",
                    "name": "Grover",
                    "category": "symmetric_crypto",
                    "target": cipher,
                    "details": grover_result
                })

            # -----------------------------------
            # 3️⃣ TLS Downgrade Attack
            # -----------------------------------
            downgrade_result = simulate_tls_downgrade(tls_version)

            results.append({
                "type": "protocol_attack",
                "name": "TLS_Downgrade",
                "category": "tls",
                "target": tls_version,
                "details": downgrade_result
            })

            # -----------------------------------
            # 4️⃣ HNDL Attack (Harvest Now Decrypt Later)
            # -----------------------------------
            if "RSA" in key_exchange:

                results.append({
                    "type": "quantum_attack",
                    "name": "HNDL",
                    "category": "data_exposure",
                    "target": "RSA Key Exchange",
                    "details": {
                        "risk": "CRITICAL",
                        "description": "Traffic can be recorded today and decrypted later using quantum computers",
                        "impact": "Long-term confidentiality loss"
                    }
                })

            elif "ECDHE" in key_exchange:

                results.append({
                    "type": "quantum_attack",
                    "name": "HNDL",
                    "category": "data_exposure",
                    "target": "ECDHE",
                    "details": {
                        "risk": "MEDIUM",
                        "description": "Forward secrecy reduces risk but still vulnerable in quantum era"
                    }
                })

            # -----------------------------------
            # 5️⃣ Forward Secrecy Check
            # -----------------------------------
            if "DHE" not in cipher:

                results.append({
                    "type": "crypto_weakness",
                    "name": "No_Forward_Secrecy",
                    "category": "tls_security",
                    "target": cipher,
                    "details": {
                        "risk": "HIGH",
                        "description": "Session keys may be compromised in future (HNDL risk)"
                    }
                })

            # -----------------------------------
            # 6️⃣ Weak Cipher Detection
            # -----------------------------------
            if any(w in cipher for w in ["RC4", "3DES"]):

                results.append({
                    "type": "crypto_weakness",
                    "name": "Weak_Cipher",
                    "category": "cipher",
                    "target": cipher,
                    "details": {
                        "risk": "CRITICAL",
                        "description": "Weak cipher detected (RC4/3DES)"
                    }
                })

            # -----------------------------------
            # 7️⃣ PQC Safe Detection
            # -----------------------------------
            if is_pqc_crypto(cipher, key_exchange, signature):

                results.append({
                    "type": "security_status",
                    "name": "Post_Quantum_Safe",
                    "category": "pqc",
                    "target": cipher or key_exchange,
                    "details": {
                        "risk": "LOW",
                        "description": "Post-Quantum cryptography detected"
                    }
                })

        except Exception as e:

            logger.error("❌ AttackAgent failed")
            logger.error(e)

        return results