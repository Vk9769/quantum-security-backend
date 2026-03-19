import logging
from datetime import datetime

logger = logging.getLogger("ReportAgent")


class ReportAgent:

    def __init__(self):
        pass

    # -----------------------------------
    # Main Report Generator
    # -----------------------------------
    def generate(self, ai_result: dict):

        try:
            asset = ai_result.get("asset", "UNKNOWN")
            attacks = ai_result.get("attack_simulation", [])
            recommendations = ai_result.get("recommendations", [])
            features = ai_result.get("features", {})

            # -----------------------------------
            # 1️⃣ Calculate Risk Level
            # -----------------------------------
            risk_level = self._calculate_risk(attacks)

            # -----------------------------------
            # 2️⃣ Build Attack Summary
            # -----------------------------------
            attack_summary = self._build_attack_summary(attacks)

            # -----------------------------------
            # 3️⃣ PQC Status
            # -----------------------------------
            pqc_status = self._detect_pqc_status(features)

            # -----------------------------------
            # 4️⃣ Key Insights
            # -----------------------------------
            insights = self._generate_insights(features, attacks)

            # -----------------------------------
            # 5️⃣ Final Report
            # -----------------------------------
            report = {
                "asset": asset,
                "timestamp": datetime.utcnow().isoformat(),

                # High-level summary
                "summary": f"{asset} analyzed. Risk level: {risk_level}",

                # Risk
                "risk_level": risk_level,

                # PQC status
                "pqc_status": pqc_status,

                # Attacks
                "attack_summary": attack_summary,
                "attack_details": attacks,

                # Recommendations
                "recommendations": recommendations,

                # Insights
                "insights": insights,

                # Raw features (useful for debugging/UI)
                "features": features
            }

            logger.info(f"📄 Report generated → {asset}")

            return report

        except Exception as e:
            logger.error("Report generation failed")
            logger.error(e)

            return self._empty_report()

    # -----------------------------------
    # Risk Calculation
    # -----------------------------------
    def _calculate_risk(self, attacks):

        max_risk = "LOW"

        for attack in attacks:

            risk = attack.get("details", {}).get("risk")

            if risk == "CRITICAL":
                return "CRITICAL"

            elif risk == "HIGH":
                max_risk = "HIGH"

            elif risk == "MEDIUM" and max_risk not in ["HIGH"]:
                max_risk = "MEDIUM"

        return max_risk

    # -----------------------------------
    # Attack Summary Builder
    # -----------------------------------
    def _build_attack_summary(self, attacks):

        summary = []

        for attack in attacks:

            name = attack.get("name")
            target = attack.get("target")
            risk = attack.get("details", {}).get("risk")

            summary.append(f"{name} attack possible on {target} (Risk: {risk})")

        return summary

    # -----------------------------------
    # PQC Detection
    # -----------------------------------
    def _detect_pqc_status(self, features):

        if features.get("pqc_support"):
            return "POST_QUANTUM_READY"

        if features.get("classical_crypto"):
            return "QUANTUM_VULNERABLE"

        return "UNKNOWN"

    # -----------------------------------
    # Insights Generator
    # -----------------------------------
    def _generate_insights(self, features, attacks):

        insights = []

        # Weak TLS
        if features.get("weak_tls"):
            insights.append("Outdated TLS version detected")

        # Weak key
        if features.get("weak_key"):
            insights.append("Weak cryptographic key size")

        # No forward secrecy
        if not features.get("forward_secrecy"):
            insights.append("No forward secrecy → HNDL risk")

        # Quantum vulnerable
        if features.get("classical_crypto"):
            insights.append("Classical cryptography vulnerable to quantum attacks")

        # PQC detected
        if features.get("pqc_support"):
            insights.append("Post-Quantum cryptography detected")

        # Attack-based insights
        for attack in attacks:
            if attack.get("name") == "Shor":
                insights.append("RSA/ECC vulnerable to Shor's algorithm")

            if attack.get("name") == "Grover":
                insights.append("Symmetric encryption weakened by Grover's algorithm")

        return list(set(insights))  # remove duplicates

    # -----------------------------------
    # Fallback
    # -----------------------------------
    def _empty_report(self):

        return {
            "asset": "UNKNOWN",
            "summary": "Report generation failed",
            "risk_level": "UNKNOWN",
            "attack_summary": [],
            "attack_details": [],
            "recommendations": [],
            "insights": [],
            "features": {}
        }