import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.ai.models.ai_agent_result import AIAgentResult

logger = logging.getLogger("AIService")


# ==========================================================
# 🔥 MAIN SAVE FUNCTION (USED BY ORCHESTRATOR)
# ==========================================================
def save_ai_result(
    db: Session,
    asset_id,
    scan_id,
    agent_name: str,
    result_type: str,
    result_data: dict,
    severity: str = None,
    confidence: float = None,
):
    """
    Save AI agent result into database.

    ⚠ IMPORTANT:
    - No commit inside this function
    - Caller must handle commit
    """

    try:
        if not asset_id:
            logger.warning("⚠ asset_id is required, skipping insert")
            return None

        ai_result = AIAgentResult(
            asset_id=asset_id,
            scan_id=scan_id,
            agent_name=agent_name,
            result_type=result_type,
            result_data=result_data,
            severity=severity,
            confidence=confidence,
        )

        db.add(ai_result)

        logger.debug(
            f"💾 AI Result queued → {agent_name} | {result_type} | asset={asset_id}"
        )

        return ai_result

    except SQLAlchemyError as e:
        logger.exception("❌ DB Error while saving AI result")
        db.rollback()
        return None

    except Exception as e:
        logger.exception("❌ Unexpected error in save_ai_result")
        db.rollback()
        return None


# ==========================================================
# 🔥 BULK SAVE (OPTIONAL FUTURE USE)
# ==========================================================
def save_multiple_ai_results(db: Session, results: list):
    """
    Save multiple AI results in one go.
    Useful for batch pipelines.
    """

    try:
        objects = []

        for r in results:
            obj = AIAgentResult(
                asset_id=r.get("asset_id"),
                scan_id=r.get("scan_id"),
                agent_name=r.get("agent_name"),
                result_type=r.get("result_type"),
                result_data=r.get("result_data"),
                severity=r.get("severity"),
                confidence=r.get("confidence"),
            )
            objects.append(obj)

        db.add_all(objects)

        logger.info(f"💾 Bulk AI results queued → {len(objects)} records")

        return objects

    except Exception:
        logger.exception("❌ Bulk insert failed")
        db.rollback()
        return []


# ==========================================================
# 🔍 FETCH AI RESULTS (FOR DASHBOARD/API)
# ==========================================================
def get_ai_results_by_asset(db: Session, asset_id):
    try:
        return (
            db.query(AIAgentResult)
            .filter(AIAgentResult.asset_id == asset_id)
            .order_by(AIAgentResult.created_at.desc())
            .all()
        )
    except Exception:
        logger.exception("❌ Failed to fetch AI results")
        return []


def get_ai_results_by_scan(db: Session, scan_id):
    try:
        return (
            db.query(AIAgentResult)
            .filter(AIAgentResult.scan_id == scan_id)
            .order_by(AIAgentResult.created_at.desc())
            .all()
        )
    except Exception:
        logger.exception("❌ Failed to fetch scan results")
        return []


# ==========================================================
# 🗑 DELETE (OPTIONAL CLEANUP)
# ==========================================================
def delete_ai_results_by_scan(db: Session, scan_id):
    try:
        deleted = (
            db.query(AIAgentResult)
            .filter(AIAgentResult.scan_id == scan_id)
            .delete()
        )

        logger.info(f"🗑 Deleted AI results → scan_id={scan_id}")

        return deleted

    except Exception:
        logger.exception("❌ Failed to delete AI results")
        db.rollback()
        return 0