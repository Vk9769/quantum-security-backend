import logging
import numpy as np

logger = logging.getLogger("RiskPredictor")


class RiskPredictor:
    """
    Hybrid Risk Prediction Model

    - Rule-based scoring (fallback)
    - ML-ready (plug XGBoost / sklearn later)
    - Returns:
        {
            score: int (0-100),
            level: LOW / MEDIUM / HIGH / CRITICAL,
            confidence: float
        }
    """

    def __init__(self, model=None):
        """
        model: optional ML model (sklearn/xgboost)
        """
        self.model = model

    # -----------------------------------
    # Convert features → vector (for ML)
    # -----------------------------------
    def _to_vector(self, features):

        return np.array([
            int(features.get("weak_tls", False)),
            int(features.get("weak_key", False)),
            int(not features.get("forward_secrecy", True)),
            int(features.get("classical_crypto", False)),
            int(features.get("pqc_support", False))
        ]).reshape(1, -1)

    # -----------------------------------
    # Rule-based fallback
    # -----------------------------------
    def _rule_based_score(self, features):

        score = 0

        if features.get("weak_tls"):
            score += 30

        if features.get("weak_key"):
            score += 40

        if not features.get("forward_secrecy"):
            score += 20

        if features.get("classical_crypto"):
            score += 30

        if features.get("pqc_support"):
            score -= 20  # reduce risk if PQC present

        return max(0, min(score, 100))

    # -----------------------------------
    # Risk level classification
    # -----------------------------------
    def _get_level(self, score):

        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    # -----------------------------------
    # MAIN PREDICTION
    # -----------------------------------
    def predict(self, features):

        try:

            # -----------------------------------
            # If ML model available → use it
            # -----------------------------------
            if self.model:

                vector = self._to_vector(features)

                score = int(self.model.predict(vector)[0])

                confidence = (
                    float(max(self.model.predict_proba(vector)[0]))
                    if hasattr(self.model, "predict_proba")
                    else 0.8
                )

                logger.info("ML risk prediction used")

            # -----------------------------------
            # Else → fallback rule-based
            # -----------------------------------
            else:

                score = self._rule_based_score(features)
                confidence = 0.7

                logger.info("Rule-based risk prediction used")

            level = self._get_level(score)

            result = {
                "score": score,
                "level": level,
                "confidence": round(confidence, 2)
            }

            logger.info(f"Risk Prediction → {result}")

            return result

        except Exception as e:

            logger.error("Risk prediction failed")
            logger.error(e)

            return {
                "score": 0,
                "level": "UNKNOWN",
                "confidence": 0.0
            }