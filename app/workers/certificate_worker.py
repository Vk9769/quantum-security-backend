import json
import logging
import time
from datetime import datetime

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.scanners.certificate_scanner import get_certificate_info
from app.services.scan_service import store_certificate_result
from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.workers.kafka_producer import send_event
from app.utils.log_streamer import setup_logger


# -------------------- LOG TO KAFKA --------------------
def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- HELPERS --------------------
def normalize_host(host: str) -> str:
    if not host:
        return ""

    return (
        str(host).strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


def parse_expiry(expiry_value):
    if not expiry_value:
        return None

    if isinstance(expiry_value, datetime):
        return expiry_value

    if isinstance(expiry_value, str):
        try:
            return datetime.fromisoformat(expiry_value)
        except Exception:
            pass

        try:
            return datetime.strptime(expiry_value, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            pass

    return None


def get_asset_with_retry(db: Session, host: str, retries: int = 2, delay: int = 2):
    for attempt in range(retries + 1):
        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == host
        ).first()

        if asset:
            return asset

        if attempt < retries:
            logger.warning(f"Asset not found → {host}, retrying...")
            time.sleep(delay)

    return None


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
        logger.warning("No scan_id for certificate event")

    if event.get("event_type") != "tls_scan_result":
        continue

    host = normalize_host(event.get("asset"))

    if not host:
        continue

    db: Session = SessionLocal()

    try:
        logger.info(f"🔐 Processing certificate → {host}")
        send_log(f"🔐 Processing certificate → {host}", scan_id)

        # ------------------------------------------------
        # 1️⃣ GET ASSET
        # ------------------------------------------------
        asset = get_asset_with_retry(db, host)

        if not asset:
            logger.warning(f"Asset still missing → {host}")
            send_log(f"⚠ Asset not found → {host}", scan_id)
            continue

        # ------------------------------------------------
        # 2️⃣ GET CERTIFICATE
        # ------------------------------------------------
        cert = None

        if event.get("certificate_subject"):
            expiry = parse_expiry(event.get("expiry"))

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
            except Exception as e:
                logger.warning(f"Fallback certificate scan failed → {host} | {e}")
                cert = None

            if not cert:
                logger.warning(f"No certificate available → {host}")
                send_log(f"❌ No certificate found → {host}", scan_id)
                continue

            cert["expiry"] = parse_expiry(cert.get("expiry"))

        # ------------------------------------------------
        # 3️⃣ CHECK DUPLICATE
        # ------------------------------------------------


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
            "scan_id": scan_id,
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