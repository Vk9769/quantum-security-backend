import logging
import json
import time
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
from app.models.cbom import CBOMInventory
from app.db.postgres import SessionLocal
from app.scanners.cbom_generator import generate_cbom
from app.services.pqc_service import store_cbom
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate
from app.workers.kafka_producer import send_event
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("CBOMWorker")


consumer = KafkaConsumer(
    "certificate-events",
    "tls-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    group_id="cbom-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("CBOM Worker Started")
print("Waiting for Kafka messages...")

for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value
    event_type = event.get("event_type")
    scan_id = event.get("scan_id")
    # Only process TLS or Certificate discoveries
    if event_type not in ["certificate_discovered", "tls_scan_result"]:
        continue

    asset = event["asset"]

    db: Session = SessionLocal()

    try:

        # -----------------------------
        # Fetch asset
        # -----------------------------
        asset_record = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset
        ).first()

        if not asset_record:

            logger.warning(f"Asset not found → {asset}, retrying")

            time.sleep(2)

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if not asset_record:
                logger.warning(f"Asset still missing → {asset}")
                continue

        # -----------------------------
        # Fetch TLS data
        # -----------------------------
        tls = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == asset_record.id
        ).order_by(TLSScanResult.scan_time.desc()).first()

        tls_data = {
            "tls_version": tls.tls_version if tls else None,
            "cipher_suite": tls.cipher_suite if tls else None,
            "key_exchange": tls.key_exchange if tls else None
        }

        # -----------------------------
        # Fetch certificate
        # -----------------------------
        cert = db.query(Certificate).filter(
            Certificate.asset_id == asset_record.id
        ).order_by(Certificate.expiry_date.desc()).first()

        if cert:
            cert_data = {
                "issuer": cert.issuer if cert else None,
                "subject": cert.subject if cert else None,
                "signature_algorithm": cert.signature_algorithm if cert else None,
                "key_size": cert.key_size if cert else None,
                "expiry": cert.expiry_date.isoformat() if cert else None
            }
        else:

            cert_data = {
                "issuer": cert.issuer if cert else None,
                "subject": cert.subject if cert else None,
                "signature_algorithm": cert.signature_algorithm if cert else None,
                "key_size": cert.key_size if cert else None,
                "expiry": cert.expiry_date.isoformat() if cert else None
            }

        # -----------------------------
        # Generate CBOM
        # -----------------------------
        cbom_data = generate_cbom(
            asset,
            tls=tls_data,
            cert=cert_data
        )


        existing_cbom = db.query(CBOMInventory).filter(
            CBOMInventory.asset_id == asset_record.id
        ).first()

        if existing_cbom:

            existing_cbom.tls_version = cbom_data["tls_version"]
            existing_cbom.cipher_suite = cbom_data["cipher_suite"]
            existing_cbom.key_exchange = cbom_data["key_exchange"]

            db.commit()

            logger.info(f"CBOM updated → {asset}")

        else:

            store_cbom(
                db,
                asset_hostname=asset,
                tls_version=cbom_data["tls_version"],
                cipher_suite=cbom_data["cipher_suite"],
                key_exchange=cbom_data["key_exchange"],
                certificate_id=cert.id if cert else None
            )

            logger.info(f"CBOM stored → {asset}")

    except Exception as e:
        logger.error(f"CBOM processing failed → {asset}")
        logger.error(e)

    finally:
        db.close()

    # -----------------------------
    # Publish CBOM event
    # -----------------------------
    cbom_event = {
        "scan_id": scan_id,
        "event_type": "cbom_generated",
        "asset": asset,
        **cbom_data
    }
    send_event("cbom-events", cbom_event, key=asset)

    logger.info(f"CBOM generated → {asset}")