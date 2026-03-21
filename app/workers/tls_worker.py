import json
import logging
import time
from datetime import datetime, UTC

from kafka import KafkaConsumer, KafkaProducer
from sqlalchemy.orm import Session

from app.scanners.tls_scanner import scan_tls
from app.db.postgres import SessionLocal
from app.models.tls import TLSScanResult
from app.models.asset_registry import AssetRegistry
from app.services.graph_service import GraphService
from app.utils.log_streamer import setup_logger
from app.workers.kafka_producer import send_event


# -------------------- HELPERS --------------------

def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


def detect_forward_secrecy(tls_version: str, cipher: str, key_exchange: str) -> bool:
    tls_version = (tls_version or "").upper().strip()
    cipher = (cipher or "").upper().strip()
    key_exchange = (key_exchange or "").upper().strip()

    # TLS 1.3 uses ephemeral key exchange by design
    if tls_version in ["TLSV1.3", "TLS1.3"]:
        return True

    # TLS 1.2 / older ciphers with DHE / ECDHE
    if "DHE" in cipher:
        return True

    # Explicit negotiated group / exchange hints
    if any(k in key_exchange for k in [
        "DHE", "ECDHE", "ECDH", "X25519", "X448", "SECP", "P-256", "P-384", "P-521",
        "KYBER", "MLKEM"
    ]):
        return True

    return False


# -------------------- LOGGING --------------------

setup_logger()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("TLSWorker")


# -------------------- INIT --------------------

graph = GraphService()

consumer = KafkaConsumer(
    "port-scan-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="tls-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

logger.info("🚀 TLS Worker Started")
print("Waiting for Kafka messages...")


# -------------------- MAIN LOOP --------------------

for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value

    scan_id = event.get("scan_id")
    asset = event.get("asset")

    try:
        if event.get("event_type") != "port_open":
            continue

        if event.get("port") != 443:
            continue

        if not asset:
            logger.warning("TLS event received without asset")
            continue

        if not scan_id:
            logger.warning(f"⚠ Missing scan_id for TLS → {asset}")

        logger.info(f"🔐 TLS Scan started → {asset}")
        send_log(f"🔐 TLS scan started → {asset}", scan_id)

        # ---------------- SCAN TLS ----------------
        try:
            result = scan_tls(asset)
        except Exception as e:
            logger.error(f"TLS scan failed → {asset}")
            logger.error(e)
            result = None

        # ---------------- FALLBACK ----------------
        if not result:
            logger.warning(f"TLS handshake failed → {asset}")
            send_log(f"❌ TLS handshake failed → {asset}", scan_id)

            try:
                graph.add_tls(asset, "UNKNOWN", "UNKNOWN")
            except Exception as e:
                logger.error("Neo4j TLS update failed")
                logger.error(e)

            producer.send("tls-events", {
                "scan_id": scan_id,
                "event_type": "tls_scan_result",
                "asset": asset,
                "tls_version": "UNKNOWN",
                "cipher_suite": "UNKNOWN",
                "key_exchange": "UNKNOWN",
                "certificate_issuer": None,
                "certificate_subject": None,
                "signature_algorithm": None,
                "key_size": None,
                "expiry": None
            })
            producer.flush()
            continue

        # Normalize extracted values
        tls_version = result.get("tls_version")
        cipher_suite = result.get("cipher_suite")
        key_exchange = result.get("key_exchange")
        forward_secrecy = detect_forward_secrecy(
            tls_version=tls_version,
            cipher=cipher_suite,
            key_exchange=key_exchange
        )

        # ---------------- DB OPERATIONS ----------------
        db: Session = SessionLocal()

        try:
            asset_record = None

            for _ in range(3):
                asset_record = db.query(AssetRegistry).filter(
                    AssetRegistry.asset_identifier == asset
                ).first()

                if asset_record:
                    break

                logger.warning(f"Asset not found → {asset}, retrying...")
                time.sleep(2)

            if not asset_record:
                logger.warning(f"Asset still missing → {asset}")
                send_log(f"⚠ Asset not found for TLS result → {asset}", scan_id)
                continue

            existing = db.query(TLSScanResult).filter(
                TLSScanResult.asset_id == asset_record.id
            ).first()

            if existing:
                existing.tls_version = tls_version
                existing.cipher_suite = cipher_suite
                existing.key_exchange = key_exchange
                existing.forward_secrecy = forward_secrecy
                existing.scan_time = datetime.now(UTC)

                logger.info(f"TLS updated → {asset}")

            else:
                tls_result = TLSScanResult(
                    asset_id=asset_record.id,
                    tls_version=tls_version,
                    cipher_suite=cipher_suite,
                    key_exchange=key_exchange,
                    forward_secrecy=forward_secrecy,
                    scan_time=datetime.now(UTC)
                )

                db.add(tls_result)
                logger.info(f"TLS stored → {asset}")

            db.commit()

            # ---------------- GRAPH UPDATE ----------------
            try:
                graph.add_tls(asset, tls_version, cipher_suite)
                logger.info(f"Graph updated → TLS for {asset}")
            except Exception as e:
                logger.error("Neo4j TLS update failed")
                logger.error(e)

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to store TLS result → {asset}")
            logger.error(e)
            send_log(f"❌ Failed to store TLS result → {asset}", scan_id)

        finally:
            db.close()

        # ---------------- SEND NEXT EVENT ----------------
        producer.send("tls-events", {
            "scan_id": scan_id,
            "event_type": "tls_scan_result",
            "asset": asset,
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "key_exchange": key_exchange,
            "certificate_issuer": result.get("certificate_issuer"),
            "certificate_subject": result.get("certificate_subject"),
            "signature_algorithm": result.get("signature_algorithm"),
            "key_size": result.get("key_size"),
            "expiry": result.get("expiry"),
            "forward_secrecy": forward_secrecy
        })
        producer.flush()

        logger.info(f"TLS event sent → {asset}")
        send_log(f"🔐 TLS scan completed → {asset}", scan_id)

    except Exception as e:
        logger.error("❌ TLS worker crashed")
        logger.error(e)
        send_log(f"❌ TLS scan failed → {asset}", scan_id)