import json
import logging

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.scanners.certificate_scanner import get_certificate_info
from app.services.scan_service import store_certificate_result
from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.workers.kafka_producer import send_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CertificateWorker")

consumer = KafkaConsumer(
    "tls-events",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Certificate Worker Started")


for message in consumer:

    event = message.value

    if event["event_type"] != "tls_scan_result":
        continue

    host = (
        event["asset"]
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )

    db: Session = SessionLocal()

    try:

        # ------------------------------------------------
        # Check if certificate already exists
        # ------------------------------------------------

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == host
        ).first()

        if not asset:
            logger.warning(f"Asset not found → {host}")
            continue

        logger.info(f"Scanning certificate → {host}")

        cert = get_certificate_info(host)

        if not cert:
            logger.warning(f"No certificate → {host}")
            continue

        cert_exists = db.query(Certificate).filter(
            Certificate.asset_id == asset.id,
            Certificate.signature_algorithm == cert["signature_algorithm"],
            Certificate.expiry_date == cert["expiry"]
        ).first()

        if cert_exists:
            logger.info(f"Certificate already exists → {host}")
            continue

        # ------------------------------------------------
        # Store certificate
        # ------------------------------------------------

        store_certificate_result(
            db,
            asset_hostname=host,
            issuer=cert["issuer"],
            subject=cert["subject"],
            expiry=cert["expiry"],
            signature_algorithm=cert["signature_algorithm"],
            key_size=cert["key_size"]
        )

        cert_event = {
            "event_type": "certificate_discovered",
            "asset": host,
            "issuer": cert["issuer"],
            "subject": cert["subject"],
            "expiry": cert["expiry"].isoformat(),
            "signature_algorithm": cert["signature_algorithm"],
            "key_size": cert["key_size"]
        }

        send_event("certificate-events", cert_event)

        logger.info(f"Certificate extracted → {host}")

    except Exception:

        logger.warning(f"Certificate scan failed → {host}")

    finally:
        db.close()