
import json
import logging
import time
from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.scanners.certificate_scanner import get_certificate_info
from app.services.scan_service import store_certificate_result
from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.workers.kafka_producer import send_event
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("CertificateWorker")

consumer = KafkaConsumer(
    "tls-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    group_id="certificate-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Certificate Worker Started")

print("Waiting for Kafka messages...")
for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value

    if event["event_type"] != "tls_scan_result":
        continue

    host = event["asset"].lower().strip()

    host = (
        host.replace("https://", "")
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

            logger.warning(f"Asset not found → {host}, retrying...")

            time.sleep(2)

            asset = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == host
            ).first()

            if not asset:
                logger.warning(f"Asset still missing → {host}")
                continue

        logger.info(f"Scanning certificate → {host}")

        try:

            cert = get_certificate_info(host)

            if not cert:
                logger.warning(f"No certificate → {host}")
                continue

        except Exception as e:

            logger.warning(f"Certificate scan failed → {host}")
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
            "scan_id": event.get("scan_id"),
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