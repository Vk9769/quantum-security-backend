import json
import logging
import time
import asyncio
from datetime import datetime
from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.scanners.certificate_scanner import get_certificate_info
from app.services.scan_service import store_certificate_result
from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.workers.kafka_producer import send_event

# 🔥 ADD THIS (LOG TO KAFKA)
def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })
    
from app.utils.log_streamer import setup_logger


# -------------------- ENABLE GLOBAL LOG STREAM --------------------
setup_logger()


# -------------------- LOGGING --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("CertificateWorker")


# -------------------- KAFKA --------------------
consumer = KafkaConsumer(
    "tls-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="certificate-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Certificate Worker Started")
print("Waiting for Kafka messages...")


# -------------------- MAIN LOOP --------------------

for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    event = message.value
    
    scan_id = event.get("scan_id")
    
    if not scan_id:
        logger.warning(f"No scan_id for certificate → {host}")

    if event.get("event_type") != "tls_scan_result":
        continue

    host = event.get("asset", "").lower().strip()

    # clean URL
    host = (
        host.replace("https://", "")
            .replace("http://", "")
            .split(":")[0]
            .strip("/")
    )

    if not host:
        continue

    db: Session = SessionLocal()

    try:

        logger.info(f"🔐 Processing certificate → {host}")
        send_log(f"🔐 Processing certificate → {host}", scan_id)

        # ------------------------------------------------
        # 1️⃣ GET ASSET
        # ------------------------------------------------

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == host
        ).first()

        if not asset:

            logger.warning(f"Asset not found → {host}, retrying...")
            send_log(f"Retrying asset lookup: {host}", scan_id)

            time.sleep(2)

            asset = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == host
            ).first()

            if not asset:
                logger.warning(f"Asset still missing → {host}")
                send_log(f"Asset not found: {host}", scan_id)
                continue

        # ------------------------------------------------
        # 2️⃣ GET CERTIFICATE
        # ------------------------------------------------

        cert = None

        if event.get("certificate_subject"):

            expiry = event.get("expiry")

            if isinstance(expiry, str):
                try:
                    expiry = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                except:
                    expiry = None

            cert = {
                "issuer": event.get("certificate_issuer"),
                "subject": event.get("certificate_subject"),
                "signature_algorithm": event.get("signature_algorithm"),
                "key_size": event.get("key_size"),
                "expiry": expiry
            }

            logger.info("Certificate obtained from TLS event")
            send_log(f"🔐 TLS certificate found → {host}", scan_id)
        else:

            logger.info("TLS event had no certificate → fallback scan")
            send_log(f"🔍 Fallback certificate scan → {host}", scan_id)

            try:
                cert = get_certificate_info(host)
            except Exception:
                cert = None

            if not cert:
                logger.warning(f"No certificate available → {host}")
                send_log(f"❌ No certificate found → {host}", scan_id)
                continue

        # ------------------------------------------------
        # 3️⃣ CHECK DUPLICATE
        # ------------------------------------------------

        cert_exists = db.query(Certificate).filter(
            Certificate.asset_id == asset.id,
            Certificate.signature_algorithm == cert.get("signature_algorithm")
        ).first()

        if cert_exists:
            logger.info(f"Certificate already exists → {host}")
            send_log(f"⚠ Certificate already exists → {host}", scan_id)
            continue

        # ------------------------------------------------
        # 4️⃣ STORE CERTIFICATE
        # ------------------------------------------------

        store_certificate_result(
            db,
            asset_hostname=host,
            issuer=cert.get("issuer"),
            subject=cert.get("subject"),
            expiry=cert.get("expiry"),
            signature_algorithm=cert.get("signature_algorithm"),
            key_size=cert.get("key_size")
        )

        # ------------------------------------------------
        # 5️⃣ SEND EVENT
        # ------------------------------------------------

        cert_event = {
            "scan_id": event.get("scan_id"),
            "event_type": "certificate_discovered",
            "asset": host,
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "expiry": cert.get("expiry").isoformat() if cert.get("expiry") else None,
            "signature_algorithm": cert.get("signature_algorithm"),
            "key_size": cert.get("key_size")
        }

        send_event("certificate-events", cert_event)

        logger.info(f"✅ Certificate stored → {host}")
        send_log(f"📜 Certificate stored → {host}", scan_id)

    except Exception as e:

        db.rollback()

        logger.error(f"❌ Certificate worker failed → {host}")
        logger.error(e)

        send_log(f"❌ Certificate scan failed → {host}", scan_id)

    finally:

        db.close()