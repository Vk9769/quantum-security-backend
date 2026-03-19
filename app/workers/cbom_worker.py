import logging
import json
import time
import asyncio

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

from app.utils.log_streamer import setup_logger


# -------------------- LOGGER SETUP --------------------
setup_logger()

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("CBOMWorker")


# -------------------- KAFKA CONSUMER --------------------
consumer = KafkaConsumer(
    "certificate-events",
    "tls-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="cbom-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 CBOM Worker Started")
print("Waiting for Kafka messages...")


def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- MAIN LOOP --------------------
for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    event = message.value
    event_type = event.get("event_type")
    scan_id = event.get("scan_id")
    
    if not scan_id:
        logger.warning(f"No scan_id for {asset}")

    if event_type not in ["certificate_discovered", "tls_scan_result"]:
        continue

    asset = event.get("asset")

    if not asset:
        continue

    db: Session = SessionLocal()

    try:

        logger.info(f"🔐 Processing CBOM → {asset}")
        send_log(f"📦 Processing CBOM → {asset}", scan_id)

        # --------------------------------
        # Fetch asset with retry
        # --------------------------------
        asset_record = None

        for _ in range(3):
            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if asset_record:
                break

            logger.warning(f"Asset not found → {asset}, retrying...")
            time.sleep(1)

        if not asset_record:
            logger.warning(f"Asset still missing → {asset}")
            send_log(f"⚠ Asset not found → {asset}", scan_id)
            continue

        # --------------------------------
        # Fetch TLS data
        # --------------------------------
        tls = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == asset_record.id
        ).order_by(TLSScanResult.scan_time.desc()).first()

        tls_data = {
            "tls_version": tls.tls_version if tls else None,
            "cipher_suite": tls.cipher_suite if tls else None,
            "key_exchange": tls.key_exchange if tls else None
        }

        # --------------------------------
        # Fetch Certificate
        # --------------------------------
        cert = db.query(Certificate).filter(
            Certificate.asset_id == asset_record.id
        ).order_by(Certificate.expiry_date.desc()).first()

        cert_data = {
            "issuer": cert.issuer if cert and cert.issuer else event.get("certificate_issuer"),
            "subject": cert.subject if cert and cert.subject else event.get("certificate_subject"),
            "signature_algorithm": (
                event.get("signature_algorithm")
                or (cert.signature_algorithm if cert else None)
            ),
            "key_size": cert.key_size if cert and cert.key_size else event.get("key_size"),
            "expiry": cert.expiry_date.isoformat() if cert and cert.expiry_date else event.get("expiry")
        }

        # --------------------------------
        # Generate CBOM
        # --------------------------------
        cbom_data = generate_cbom(
            asset,
            tls=tls_data,
            cert=cert_data
        )

        logger.info(f"⚙️ CBOM generated → {asset}")
        send_log(f"📦 CBOM generated → {asset}", scan_id)

        # --------------------------------
        # Store CBOM
        # --------------------------------
        existing_cbom = db.query(CBOMInventory).filter(
            CBOMInventory.asset_id == asset_record.id
        ).first()

        if existing_cbom:

            existing_cbom.tls_version = cbom_data["tls_version"]
            existing_cbom.cipher_suite = cbom_data["cipher_suite"]
            existing_cbom.key_exchange = cbom_data["key_exchange"]

            db.commit()

            logger.info(f"🔄 CBOM updated → {asset}")
            send_log(f"🔄 CBOM updated → {asset}", scan_id)

        else:

            store_cbom(
                db,
                asset_hostname=asset,
                tls_version=cbom_data["tls_version"],
                cipher_suite=cbom_data["cipher_suite"],
                key_exchange=cbom_data["key_exchange"],
                certificate_id=cert.id if cert else None
            )

            logger.info(f"💾 CBOM stored → {asset}")
            send_log(f"💾 CBOM stored → {asset}", scan_id)

        # --------------------------------
        # Publish CBOM event
        # --------------------------------
        cbom_event = {
            "scan_id": scan_id,
            "event_type": "cbom_generated",
            "asset": asset,
            **cbom_data
        }

        send_event("cbom-events", cbom_event, key=asset)

        logger.info(f"📤 CBOM event sent → {asset}")
        send_log(f"📤 CBOM event sent → {asset}", scan_id)

    except Exception as e:

        db.rollback()

        logger.error(f"❌ CBOM processing failed → {asset}")
        logger.exception(e)

        send_log(f"❌ CBOM failed → {asset}", scan_id)

    finally:
        db.close()