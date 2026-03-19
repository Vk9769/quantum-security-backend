import logging

from app.ai.feature_store import extract_features

# Core Agents
from app.ai.agents.attack_agent import AttackAgent
from app.ai.agents.scan_agent import ScanAgent
from app.ai.agents.crypto_agent import CryptoAgent
from app.ai.agents.pqc_agent import PQCAgent
from app.ai.agents.report_agent import ReportAgent

# Reasoning
from app.ai.reasoning.pqc_recommender import recommend_pqc
from app.ai.reasoning.attack_graph_builder import build_attack_paths

# ML Models
from app.ai.models.risk_predictor import RiskPredictor
from app.ai.models.anomaly_model import AnomalyModel

# Simulators
from app.ai.simulators.mitm_simulator import simulate_mitm

# LLM
from app.ai.llm.llm_router import LLMRouter
from app.ai.llm.prompts import build_security_prompt

logger = logging.getLogger("AISOC")


class AISOC:

    def __init__(self):

        # -----------------------------
        # Core Agents
        # -----------------------------
        self.attack_agent = AttackAgent()
        self.scan_agent = ScanAgent()
        self.crypto_agent = CryptoAgent()
        self.pqc_agent = PQCAgent()
        self.report_agent = ReportAgent()

        # -----------------------------
        # ML Models
        # -----------------------------
        self.risk_model = RiskPredictor()
        self.anomaly_model = AnomalyModel()

        # -----------------------------
        # LLM (SAFE INIT)
        # -----------------------------
        try:
            self.llm = LLMRouter()
            logger.info("✅ LLM Router initialized")
        except Exception as e:
            logger.error("❌ LLM init failed")
            logger.error(e)
            self.llm = None

    # ======================================================
    # 🔥 MAIN ANALYSIS ENGINE
    # ======================================================
    def analyze(self, tls_event: dict):

        try:
            # -----------------------------------
            # 1️⃣ Validate input
            # -----------------------------------
            if not isinstance(tls_event, dict):
                logger.error("Invalid TLS event format")
                return self._empty_response()

            asset = tls_event.get("asset", "UNKNOWN")

            logger.info(f"🤖 AI SOC Analysis started → {asset}")

            # -----------------------------------
            # 2️⃣ Feature Extraction
            # -----------------------------------
            features = extract_features(tls_event)

            logger.debug(f"Features → {features}")

            # -----------------------------------
            # 3️⃣ Attack Simulation
            # -----------------------------------
            attacks = self.attack_agent.run(features)

            logger.info(f"⚔ Attack Simulation → {attacks}")

            # -----------------------------------
            # 4️⃣ Crypto Analysis
            # -----------------------------------
            crypto_issues = self.crypto_agent.analyze(features)

            # -----------------------------------
            # 5️⃣ PQC Recommendations
            # -----------------------------------
            recommendations = recommend_pqc(features)

            pqc_plan = self.pqc_agent.plan_migration(features)

            logger.info(f"🧠 Recommendations → {recommendations}")

            # -----------------------------------
            # 6️⃣ Attack Graph
            # -----------------------------------
            attack_paths = build_attack_paths(asset, features)

            # -----------------------------------
            # 7️⃣ Scan Decisions (AUTO ACTION)
            # -----------------------------------
            scan_actions = self.scan_agent.decide_next_steps(features)

            # -----------------------------------
            # 8️⃣ MITM Simulation
            # -----------------------------------
            mitm_result = simulate_mitm(features)

            # -----------------------------------
            # 9️⃣ ML Risk Score
            # -----------------------------------
            risk_score = self.risk_model.predict(features)

            # -----------------------------------
            # 🔟 Anomaly Detection
            # -----------------------------------
            anomalies = self.anomaly_model.detect(features)

            # -----------------------------------
            # 1️⃣1️⃣ LLM Explanation (SAFE)
            # -----------------------------------
            explanation = None

            if self.llm:
                try:
                    prompt = build_security_prompt(
                        features,
                        attacks,
                        recommendations
                    )

                    explanation = self.llm.run(
                        task="security_explanation",
                        prompt=prompt
                    )

                    # fallback if LLM fails
                    if "LLM_ERROR" in str(explanation):
                        explanation = self._fallback_explanation(
                            features, attacks
                        )

                    logger.info("🧠 LLM Explanation generated")

                except Exception as e:
                    logger.warning("⚠ LLM failed → using fallback")
                    explanation = self._fallback_explanation(
                        features, attacks
                    )

            # -----------------------------------
            # 1️⃣2️⃣ Final Report
            # -----------------------------------
            report = self.report_agent.generate({
                "asset": asset,
                "attack_simulation": attacks,
                "recommendations": recommendations
            })

            # -----------------------------------
            # 1️⃣3️⃣ Final Response
            # -----------------------------------
            result = {
                "asset": asset,
                "features": features,

                # AI Core
                "attack_simulation": attacks,
                "attack_paths": attack_paths,
                "recommendations": recommendations,

                # Advanced AI
                "crypto_issues": crypto_issues,
                "pqc_plan": pqc_plan,
                "scan_actions": scan_actions,
                "mitm_simulation": mitm_result,

                # ML
                "risk_score": risk_score,
                "anomalies": anomalies,

                # LLM
                "explanation": explanation,

                # Report
                "report": report
            }

            logger.info(f"✅ AI SOC completed → {asset}")

            return result

        except Exception as e:

            logger.error(f"❌ AI SOC failed → {e}")

            return self._empty_response()

    # ======================================================
    # 🔥 FALLBACK EXPLANATION (NO LLM)
    # ======================================================
    def _fallback_explanation(self, features, attacks):

        return f"""
        Security Analysis Summary:

        TLS Version: {features.get('tls_version')}
        Cipher: {features.get('cipher')}

        Detected Risks:
        - Classical cryptography vulnerable to quantum attacks
        - Potential lack of forward secrecy

        Recommended:
        - Upgrade to Post-Quantum Cryptography (Kyber/Dilithium)
        - Ensure forward secrecy enabled

        Attacks Simulated:
        {len(attacks)} attack vectors identified
        """

    # ======================================================
    # SAFE DEFAULT
    # ======================================================
    def _empty_response(self):

        return {
            "asset": "UNKNOWN",
            "features": {},
            "attack_simulation": [],
            "attack_paths": [],
            "recommendations": [],
            "crypto_issues": [],
            "pqc_plan": [],
            "scan_actions": [],
            "mitm_simulation": {},
            "risk_score": 0,
            "anomalies": [],
            "explanation": None,
            "report": {}
        }