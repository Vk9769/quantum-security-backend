import json
import logging
import time

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.services.graph_service import GraphService
from app.ai.quantum_risk_analyzer import analyze_quantum_risk
from app.ai.agents.orchestrator_agent import AISOC

from app.workers.kafka_producer import send_alert, send_event
from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.models.risk import AssetRiskScore

from app.utils.scan_control import check_scan_control
from app.utils.checkpoint import save_checkpoint, get_checkpoint

from app.services.ai_agent_service import save_ai_result
from app.services.pqc_service import update_cbom_quantum_risk, store_pqc_analysis


# -------------------- INIT --------------------
graph = GraphService()
ai_soc = AISOC()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logger = logging.getLogger("RiskWorker")


# -------------------- HELPERS --------------------
def normalize_asset(asset: str) -> str:
    if not asset:
        return ""

    asset = str(asset).strip().lower()

    if "://" in asset:
        asset = asset.split("://")[1]

    asset = asset.split("/")[0]
    asset = asset.split(":")[0]

    return asset


def get_asset_record(db: Session, asset: str):
    return db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset
    ).first()


def upsert_asset_risk(db, asset_id, score):
    category = "LOW"

    if score >= 70:
        category = "CRITICAL"
    elif score >= 40:
        category = "HIGH"
    elif score >= 20:
        category = "MEDIUM"

    existing = db.query(AssetRiskScore).filter(
        AssetRiskScore.asset_id == asset_id
    ).first()

    if existing:
        existing.score = score
        existing.risk_category = category
    else:
        db.add(AssetRiskScore(
            asset_id=asset_id,
            score=score,
            risk_category=category
        ))


def calculate_risk_score(base=0, quantum=False, vulnerability=False):
    score = base

    if vulnerability:
        score += 70
    if quantum:
        score += 40

    return min(score, 100)


def detect_pqc(event):
    # Always rely on analyzer (single source of truth)
    return analyze_quantum_risk(event)


# -------------------- KAFKA --------------------
consumer = KafkaConsumer(
    "vulnerability-events",
    "cbom-events",
    "risk-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    enable_auto_commit=True,
    group_id="risk-worker",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Risk Worker Started")


# -------------------- MAIN LOOP --------------------
for message in consumer:
    event = message.value
    print("EVENT:", event)

    event_type = event.get("event_type")
    asset = normalize_asset(event.get("asset"))

    logger.info(f"🔥 Processing → {event_type} → {asset}")
    scan_id = event.get("scan_id")

    if not scan_id:
        continue

    status = check_scan_control(scan_id)
    if status == "paused":
        time.sleep(2)
        continue
    if status == "stopped":
        continue

    db: Session = SessionLocal()

    try:
        asset = normalize_asset(event.get("asset"))
        if not asset:
            continue

        graph.create_asset("unknown", asset)

        # ============================================
        # 1️⃣ VULNERABILITY
        # ============================================
        if event_type == "vulnerability_detected":

            cve = event.get("cve") or "UNKNOWN"

            graph.add_vulnerability(asset, cve)

            risk_score = calculate_risk_score(vulnerability=True)

            asset_record = get_asset_record(db, asset)
            if not asset_record:
                logger.error(f"❌ Asset not found → {asset}")
                continue

            upsert_asset_risk(db, asset_record.id, risk_score)
            db.commit()

            if risk_score >= 70:
                send_alert(asset, "HIGH", f"Critical vulnerability {cve}", scan_id)

        # ============================================
        # 2️⃣ AI + QUANTUM RISK
        # ============================================
        elif event_type in ["analyze_risk", "tls_scan_result", "cbom_generated"]:

            logger.info(f"🧠 AI Trigger → {asset}")

            quantum_risk = detect_pqc(event)

            if quantum_risk == "CRITICAL":
                risk_score = 80
            elif quantum_risk == "NOT_QUANTUM_SAFE":
                risk_score = 60
            elif quantum_risk == "HYBRID_POST_QUANTUM":
                risk_score = 30
            elif quantum_risk == "POST_QUANTUM_SAFE":
                risk_score = 10
            else:
                risk_score = 20

            asset_record = get_asset_record(db, asset)
            if not asset_record:
                logger.error(f"❌ Asset not found → {asset}")
                continue

            # ---------------- AI ----------------
            try:
                ai_input = {**event, "asset_id": asset_record.id}

                ai_result = ai_soc.analyze(ai_input) or {}

                logger.info(f"AI OUTPUT → {ai_result}")

                # SAVE ALL RESULTS
                SKIP_KEYS = ["asset"]

                for key, value in ai_result.items():
                    if key in SKIP_KEYS or not value:
                        continue

                    try:
                        if isinstance(value, (dict, list)):
                            data = value
                        else:
                            data = {"value": value}

                        save_ai_result(
                            db,
                            asset_record.id,
                            scan_id,
                            key,
                            key,
                            data
                        )

                    except Exception as e:
                        logger.error(f"❌ Failed to save AI result → {key}")

            except Exception as e:
                logger.error("AI FAILED")
                logger.error(e)
                
            logger.info(
                f"Quantum Analysis → {asset} | "
                f"Risk={quantum_risk} | "
                f"KeyExchange={event.get('key_exchange')} | "
                f"Signature={event.get('signature_algorithm')}"
)
            # ---------------- STORE ----------------
            pqc_ready = quantum_risk in ["HYBRID_POST_QUANTUM", "POST_QUANTUM_SAFE"]

            # Force correct detection for hybrid key exchange
            if "MLKEM" in str(event.get("key_exchange", "")).upper():
                pqc_ready = True
                
            algorithm = (
                event.get("signature_algorithm")
                or event.get("key_exchange")
                or "UNKNOWN"
            )

            store_pqc_analysis(db, asset_record.id, algorithm, pqc_ready)
            update_cbom_quantum_risk(db, asset_record.id, quantum_risk)

            upsert_asset_risk(db, asset_record.id, risk_score)

            db.commit()

            # ---------------- ALERT ----------------
            if quantum_risk in ["CRITICAL", "NOT_QUANTUM_SAFE"]:
                send_alert(
                    asset,
                    "HIGH",
                    f"Quantum Risk: {quantum_risk}",
                    scan_id
                )

            # ---------------- EVENT ----------------
            send_event("ai-security-events", {
                "scan_id": scan_id,
                "event_type": "ai_security_analysis",
                "asset": asset,
                "quantum_risk": quantum_risk,
                "risk_score": risk_score,
                "pqc_ready": pqc_ready
            })

    except Exception as e:
        db.rollback()
        logger.error("❌ Worker crash")
        logger.error(e)

    finally:
        db.close()