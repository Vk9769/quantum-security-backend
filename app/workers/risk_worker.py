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

# ✅ SCAN CONTROL
from app.utils.scan_control import check_scan_control

# ✅ CHECKPOINT IMPORT
from app.utils.checkpoint import save_checkpoint, get_checkpoint

from app.services.pqc_service import (
    update_cbom_quantum_risk,
    store_pqc_analysis
)

from app.services.risk_service import store_asset_risk


# -------------------- LOG SENDER --------------------
def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- HELPERS --------------------
def normalize_asset(asset: str) -> str:
    if not asset:
        return ""
    return (
        str(asset).strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


def get_asset_record_with_retry(db: Session, asset: str, retries: int = 2, delay: int = 2):
    for attempt in range(retries + 1):

        status = check_scan_control(current_scan_id)
        if status == "stopped":
            return None
        if status == "paused":
            time.sleep(2)
            continue

        asset_record = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset
        ).first()

        if asset_record:
            return asset_record

        if attempt < retries:
            logger.warning(f"Asset not found → {asset}, retrying...")
            time.sleep(delay)

    return None


def calculate_risk_score(base=0, quantum=False, vulnerability=False):
    score = base

    if vulnerability:
        score += 70

    if quantum:
        score += 40

    return min(score, 100)


def get_quantum_risk_score(quantum_risk: str) -> int:
    if quantum_risk == "CRITICAL":
        return calculate_risk_score(base=80, quantum=True)

    if quantum_risk == "NOT_QUANTUM_SAFE":
        return calculate_risk_score(base=40, quantum=True)

    if quantum_risk == "HYBRID_POST_QUANTUM":
        return calculate_risk_score(base=10)

    if quantum_risk == "POST_QUANTUM_SAFE":
        return calculate_risk_score(base=0)

    return calculate_risk_score(base=5)


def is_pqc_ready(quantum_risk: str) -> bool:
    return quantum_risk in ["HYBRID_POST_QUANTUM", "POST_QUANTUM_SAFE"]


def get_alert_severity(quantum_risk: str) -> str:
    if quantum_risk == "CRITICAL":
        return "HIGH"
    if quantum_risk == "NOT_QUANTUM_SAFE":
        return "MEDIUM"
    return "LOW"


# -------------------- INIT --------------------
graph = GraphService()
ai_soc = AISOC()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("RiskWorker")


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

logger.info("🚀 Risk Worker Started with AI SOC")
print("Waiting for Kafka messages...")


# -------------------- MAIN LOOP --------------------
for message in consumer:
    event = message.value
    print("KAFKA MESSAGE RECEIVED:", event)

    event_type = event.get("event_type")
    scan_id = event.get("scan_id")

    current_scan_id = scan_id

    status = check_scan_control(scan_id)

    if status == "paused":
        time.sleep(2)
        continue

    if status == "stopped":
        logger.info(f"⛔ Scan stopped → {scan_id}")
        continue

    checkpoint = get_checkpoint(scan_id)

    if event_type != "analyze_risk":
        if checkpoint and checkpoint.get("stage") not in [None, "risk_analysis"]:
            continue

    db: Session = SessionLocal()

    try:
        if not scan_id:
            logger.warning(f"⚠ Missing scan_id for event: {event_type}")

        # ============================================
        # 1️⃣ VULNERABILITY EVENTS
        # ============================================
        if event_type == "vulnerability_detected":

            if check_scan_control(scan_id) == "stopped":
                continue

            asset = normalize_asset(event.get("asset"))
            cve = event.get("cve") or "UNKNOWN"

            if not asset:
                continue

            if checkpoint:
                last_asset = checkpoint.get("last_asset")
                if last_asset and asset != last_asset:
                    continue

            save_checkpoint(scan_id, "risk_analysis", last_asset=asset)

            graph.create_asset("unknown", asset)
            graph.add_vulnerability(asset, cve)

            logger.info(f"⚠ Vulnerability → {asset} {cve}")
            send_log(f"⚠ Vulnerability → {asset} {cve}", scan_id)

            risk_score = calculate_risk_score(vulnerability=True)

            logger.info(f"📊 Risk Score → {asset} = {risk_score}")
            send_log(f"📊 Risk score → {asset}: {risk_score}", scan_id)

            if risk_score >= 70:
                send_alert(asset, "HIGH", f"Critical vulnerability {cve}", scan_id)

            asset_record = get_asset_record_with_retry(db, asset)

            if not asset_record:
                continue

            store_asset_risk(db, asset_record.id, risk_score)

        # ============================================
        # 🔥 analyze_risk (FIXED ONLY HERE)
        # ============================================
        elif event_type == "analyze_risk":

            asset = normalize_asset(event.get("asset"))

            if not asset:
                continue

            logger.info(f"🧠 Risk trigger received → {asset}")
            send_log(f"🧠 Risk analysis started → {asset}", scan_id)

            status = check_scan_control(scan_id)
            if status == "stopped":
                continue
            if status == "paused":
                time.sleep(2)
                continue

            if checkpoint:
                last_asset = checkpoint.get("last_asset")
                if last_asset and asset != last_asset:
                    continue

            save_checkpoint(scan_id, "risk_analysis", last_asset=asset)

            graph.create_asset("unknown", asset)

            if check_scan_control(scan_id) == "stopped":
                continue

            quantum_risk = analyze_quantum_risk(event)

            logger.info(f"⚛ Quantum Risk → {asset} | {event.get('signature_algorithm')} | {quantum_risk}")
            send_log(f"⚛ Quantum risk → {asset} ({quantum_risk})", scan_id)

            risk_score = get_quantum_risk_score(quantum_risk)

            logger.info(f"📊 Risk Score → {asset} = {risk_score}")
            send_log(f"📊 Risk score → {asset}: {risk_score}", scan_id)

            if check_scan_control(scan_id) == "stopped":
                continue

            # ✅ FIX: GET asset_record BEFORE AI
            asset_record = get_asset_record_with_retry(db, asset)
            if not asset_record:
                continue

            try:
                ai_input = {
                    **event,
                    "asset_id": asset_record.id  # ✅ FIX
                }

                ai_result = ai_soc.analyze(ai_input) or {}
                attack_simulation = ai_result.get("attack_simulation", [])
                recommendations = ai_result.get("recommendations", [])
                attack_paths = ai_result.get("attack_paths", [])
            except Exception as e:
                logger.error("AI SOC failed")
                logger.error(e)
                attack_simulation, recommendations, attack_paths = [], [], []

            if quantum_risk in ["NOT_QUANTUM_SAFE", "CRITICAL"]:
                send_alert(asset, get_alert_severity(quantum_risk),
                           f"Quantum vulnerable crypto ({quantum_risk})", scan_id)

            graph.add_risk(asset, risk_score, quantum_risk)

            algorithm = (
                event.get("signature_algorithm")
                or event.get("key_exchange")
                or event.get("cipher_suite")
                or "UNKNOWN"
            )

            pqc_ready = is_pqc_ready(quantum_risk)

            store_pqc_analysis(db, asset_record.id, algorithm, pqc_ready)
            update_cbom_quantum_risk(db, asset_record.id, quantum_risk)
            store_asset_risk(db, asset_record.id, risk_score)

            send_event("ai-security-events", {
                "scan_id": scan_id,
                "event_type": "ai_security_analysis",
                "asset": asset,
                "quantum_risk": quantum_risk,
                "risk_score": risk_score,
                "pqc_ready": pqc_ready,
                "attack_simulation": attack_simulation,
                "recommendations": recommendations,
                "attack_paths": attack_paths
            })

            logger.info(f"📤 AI event sent → {asset}")
            send_log(f"✅ Risk processing completed → {asset}", scan_id)

    except Exception as e:
        db.rollback()
        logger.error("❌ Risk worker crashed")
        logger.error(e)
        send_log("❌ Risk processing failed", scan_id)

    finally:
        db.close()