import json
import logging
import time
from datetime import datetime, UTC

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.scanners.tls_scanner import scan_tls
from app.db.postgres import SessionLocal
from app.models.tls import TLSScanResult
from app.models.asset_registry import AssetRegistry
from app.services.graph_service import GraphService
from app.utils.log_streamer import setup_logger
from app.workers.kafka_producer import send_event

# ✅ CONTROL
from app.utils.scan_control import check_scan_control

# ✅ CHECKPOINT
from app.utils.checkpoint import save_checkpoint, get_checkpoint


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

    if tls_version in ["TLSV1.3", "TLS1.3"]:
        return True

    if "DHE" in cipher:
        return True

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

logger.info("🚀 TLS Worker Started")
print("Waiting for Kafka messages...")


# -------------------- MAIN LOOP --------------------

for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value

    scan_id = event.get("scan_id")

    # ============================================
    # 🔥 GLOBAL CONTROL (FAST CHECK)
    # ============================================
    status = check_scan_control(scan_id)

    if status == "paused":
        time.sleep(2)
        continue

    if status == "stopped":
        logger.info(f"⛔ Scan stopped → {scan_id}")
        continue

    try:
        event_type = event.get("event_type")

        # ✅ FIX: SUPPORT BOTH EVENTS
        if event_type == "port_open":
            if event.get("port") != 443:
                continue
            asset = event.get("asset")

        elif event_type == "tls_scan_requested":
            asset = event.get("asset")

        else:
            continue

        if not asset:
            logger.warning("TLS event received without asset")
            continue

        if not scan_id:
            logger.warning(f"⚠ Missing scan_id for TLS → {asset}")

        # ==============================
        # CHECKPOINT RESUME LOGIC
        # ==============================
        checkpoint = get_checkpoint(scan_id)

        skip = False
        if checkpoint:
            last_asset = checkpoint.get("last_asset")
            skip = True if last_asset else False
        else:
            last_asset = None

        if skip:
            if asset == last_asset:
                skip = False
            else:
                logger.info(f"⏭ Skipping already processed TLS → {asset}")
                continue

        # ============================================
        # 🔥 CONTROL BEFORE SCAN (CRITICAL)
        # ============================================
        status = check_scan_control(scan_id)

        if status == "stopped":
            logger.info(f"⛔ Stopped before TLS scan → {asset}")
            continue

        if status == "paused":
            time.sleep(2)
            continue

        logger.info(f"🔐 TLS Scan started → {asset}")
        send_log(f"🔐 TLS scan started → {asset}", scan_id)

        # SAVE CHECKPOINT
        save_checkpoint(
            scan_id=scan_id,
            stage="tls_scan",
            last_asset=asset
        )

        db: Session = SessionLocal()

        # ============================================
        # 🔥 RUN TLS SCAN (BLOCKING)
        # ============================================
        try:
            result = scan_tls(asset)
        except Exception as e:
            logger.error(f"TLS scan failed → {asset}")
            logger.error(e)
            result = None

        # ============================================
        # 🔥 CONTROL AFTER SCAN
        # ============================================
        status = check_scan_control(scan_id)

        if status == "stopped":
            logger.info(f"⛔ Stopped after TLS scan → {asset}")
            db.close()
            continue

        if not result:
            logger.warning(f"TLS handshake failed → {asset}")
            send_log(f"❌ TLS handshake failed → {asset}", scan_id)

            try:
                graph.add_tls(asset, "UNKNOWN", "UNKNOWN")
            except Exception as e:
                logger.error("Neo4j TLS update failed")
                logger.error(e)

            send_event("tls-events", {
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
            }, key=asset)

            db.close()
            continue

        tls_version = result.get("tls_version")
        cipher_suite = result.get("cipher_suite")
        key_exchange = result.get("key_exchange")

        forward_secrecy = detect_forward_secrecy(
            tls_version=tls_version,
            cipher=cipher_suite,
            key_exchange=key_exchange
        )

        try:
            asset_record = None

            for _ in range(3):

                status = check_scan_control(scan_id)

                if status == "stopped":
                    logger.info(f"⛔ Stopped during DB lookup → {asset}")
                    break

                if status == "paused":
                    time.sleep(2)
                    continue

                asset_record = db.query(AssetRegistry).filter(
                    AssetRegistry.asset_identifier == asset
                ).first()

                if asset_record:
                    break

                time.sleep(2)

            if not asset_record:
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

            db.commit()

            try:
                graph.add_tls(asset, tls_version, cipher_suite)
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

        send_event("tls-events", {
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
        }, key=asset)

        logger.info(f"TLS event sent → {asset}")
        send_log(f"🔐 TLS scan completed → {asset}", scan_id)

    except Exception as e:
        logger.error("❌ TLS worker crashed")
        logger.error(e)
        send_log(f"❌ TLS scan failed → {asset}", scan_id)