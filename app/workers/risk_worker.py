import json
import logging
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
import time
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

graph = GraphService()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("RiskWorker")


consumer = KafkaConsumer(
    "vulnerability-events",
    "cbom-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    group_id="risk-worker",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Risk Worker Started")


def calculate_risk_score(base=0, quantum=False, vulnerability=False):

    score = base

    if vulnerability:
        score += 70

    if quantum:
        score += 40

    if score > 100:
        score = 100

    return score

print("Waiting for Kafka messages...")
for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value
    event_type = event.get("event_type")
    scan_id = event.get("scan_id")
    # -----------------------------------
    # Vulnerability Events
    # -----------------------------------
    if event_type == "vulnerability_detected":

        asset = event["asset"]
        cve = event["cve"]
        graph.add_vulnerability(asset, cve)

        logger.info(f"⚠ Vulnerability detected → {asset} {cve}")

        risk_score = calculate_risk_score(vulnerability=True)

        logger.info(f"📊 Risk Score → {asset} = {risk_score}")
        if risk_score >= 70:

                    send_alert(
                        asset,
                        "HIGH",
                        f"Critical vulnerability {cve} detected",
                        scan_id
                    )
        db: Session = SessionLocal()
    
        try:

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

        finally:
            db.close()

    # -----------------------------------
    # Quantum Crypto Risk
    # -----------------------------------
    elif event_type == "cbom_generated":

        asset = event["asset"]

        quantum_risk = analyze_quantum_risk(event)

        logger.info(
            f"⚛ Quantum Risk → {asset} "
            f"Algo={event.get('signature_algorithm')} "
            f"Risk={quantum_risk}"
        )

        if quantum_risk == "NOT_QUANTUM_SAFE":
            risk_score = calculate_risk_score(quantum=True)
        else:
            risk_score = calculate_risk_score()

        logger.info(f"📊 Risk Score → {asset} = {risk_score}")

        # Send alert if crypto unsafe
        if quantum_risk == "NOT_QUANTUM_SAFE":

           send_alert(
                asset,
                "MEDIUM",
                f"Quantum unsafe cryptography detected",
                scan_id
            )

        # -----------------------------------
        # Store in Neo4j
        # -----------------------------------

        graph.add_risk(asset, risk_score, quantum_risk)

        # -----------------------------------
        # Store in PostgreSQL
        # -----------------------------------

        db: Session = SessionLocal()

        try:

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

            # Store PQC analysis
            store_pqc_analysis(
                db,
                asset_record.id,
                algorithm,
                pqc_ready
            )

            # Update CBOM quantum risk
            update_cbom_quantum_risk(
                db,
                asset_record.id,
                quantum_risk
            )

            # Store risk score
            store_asset_risk(
                db,
                asset_record.id,
                risk_score
            )

        except Exception as e:

            logger.error("Risk processing failed")
            logger.error(e)

        finally:
            db.close()