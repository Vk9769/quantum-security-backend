import json
import logging
import time

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.services.graph_service import GraphService
from app.ai.quantum_risk_analyzer import analyze_quantum_risk
from app.workers.kafka_producer import send_alert
from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry

from app.services.pqc_service import (
    update_cbom_quantum_risk,
    store_pqc_analysis
)

from app.services.risk_service import store_asset_risk

from app.workers.kafka_producer import send_event

def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- LOGGING --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("RiskWorker")


# -------------------- GRAPH --------------------
graph = GraphService()


# -------------------- KAFKA --------------------
consumer = KafkaConsumer(
    "vulnerability-events",
    "cbom-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    enable_auto_commit=True,
    group_id="risk-worker",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Risk Worker Started")
print("Waiting for Kafka messages...")


# -------------------- HELPERS --------------------
def calculate_risk_score(base=0, quantum=False, vulnerability=False):

    score = base

    if vulnerability:
        score += 70

    if quantum:
        score += 40

    return min(score, 100)


# -------------------- MAIN LOOP --------------------
for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    db: Session = SessionLocal()

    try:
        event = message.value
        event_type = event.get("event_type")
        scan_id = event.get("scan_id")
        
        if not scan_id:
            logger.warning(f"⚠ Missing scan_id for event: {event_type}")

        # -----------------------------------
        # VULNERABILITY EVENTS
        # -----------------------------------
        if event_type == "vulnerability_detected":

            asset = event.get("asset")
            cve = event.get("cve")

            if not asset:
                continue

            graph.create_asset("unknown", asset)
            graph.add_vulnerability(asset, cve)

            logger.info(f"⚠ Vulnerability detected → {asset} {cve}")
            send_log(f"⚠ Vulnerability detected → {asset} {cve}", scan_id)

            risk_score = calculate_risk_score(vulnerability=True)

            logger.info(f"📊 Risk Score → {asset} = {risk_score}")
            send_log(f"📊 Risk score → {asset}: {risk_score}", scan_id)

            if risk_score >= 70:
                send_alert(
                    asset,
                    "HIGH",
                    f"Critical vulnerability {cve} detected",
                    scan_id
                )

            # DB STORE
            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if not asset_record:
                logger.warning(f"Asset not found → {asset}")
                continue

            store_asset_risk(
                db,
                asset_record.id,
                risk_score
            )

        # -----------------------------------
        # QUANTUM / CBOM EVENTS
        # -----------------------------------
        elif event_type == "cbom_generated":

            asset = event.get("asset")

            if not asset:
                continue

            graph.create_asset("unknown", asset)

            quantum_risk = analyze_quantum_risk(event)

            logger.info(
                f"⚛ Quantum Risk → {asset} "
                f"Algo={event.get('signature_algorithm')} "
                f"Risk={quantum_risk}"
            )

            send_log(f"⚛ Quantum risk → {asset} ({quantum_risk})", scan_id)

            # CALCULATE SCORE
            if quantum_risk == "CRITICAL":
                risk_score = calculate_risk_score(base=80, quantum=True)

            elif quantum_risk == "NOT_QUANTUM_SAFE":
                risk_score = calculate_risk_score(base=40, quantum=True)

            elif quantum_risk == "HYBRID_POST_QUANTUM":
                risk_score = calculate_risk_score(base=10)

            elif quantum_risk == "POST_QUANTUM_SAFE":
                risk_score = calculate_risk_score(base=0)

            else:
                risk_score = calculate_risk_score(base=5)

            logger.info(f"📊 Risk Score → {asset} = {risk_score}")
            send_log(f"📊 Risk score → {asset}: {risk_score}", scan_id)

            # ALERT
            if quantum_risk in ["NOT_QUANTUM_SAFE", "CRITICAL"]:
                send_alert(
                    asset,
                    "MEDIUM",
                    f"Quantum vulnerable cryptography detected ({quantum_risk})",
                    scan_id
                )

            # GRAPH
            graph.add_risk(asset, risk_score, quantum_risk)

            # ---------------- DB ----------------
            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if not asset_record:
                logger.warning(f"Asset not found → {asset}, retrying...")
                time.sleep(2)

                asset_record = db.query(AssetRegistry).filter(
                    AssetRegistry.asset_identifier == asset
                ).first()

                if not asset_record:
                    logger.warning(f"Asset still missing → {asset}")
                    continue

            algorithm = event.get("signature_algorithm") or event.get("cipher_suite")
            pqc_ready = quantum_risk != "NOT_QUANTUM_SAFE"

            # STORE PQC
            store_pqc_analysis(
                db,
                asset_record.id,
                algorithm,
                pqc_ready
            )

            # UPDATE CBOM
            update_cbom_quantum_risk(
                db,
                asset_record.id,
                quantum_risk
            )

            # STORE RISK
            store_asset_risk(
                db,
                asset_record.id,
                risk_score
            )

    except Exception as e:

        db.rollback()

        logger.error("❌ Risk worker crashed")
        logger.error(e)

        send_log("❌ Risk processing failed", scan_id)

    finally:
        db.close()