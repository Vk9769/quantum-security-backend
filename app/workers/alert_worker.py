import json
import logging
import time
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
from datetime import datetime, UTC

from app.db.postgres import SessionLocal
from app.models.alert import Alert
from app.models.asset_registry import AssetRegistry
from app.workers.kafka_producer import send_event

# ✅ CONTROL
from app.utils.scan_control import check_scan_control

# ✅ NEW (RUNTIME CONTROL - INSTANT STOP)
from app.utils.runtime_control import is_stopped, is_paused

# ✅ CHECKPOINT
from app.utils.checkpoint import save_checkpoint


# -------------------- LOGGING --------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)

logger = logging.getLogger("AlertWorker")


# -------------------- SEND LOG --------------------

def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- KAFKA --------------------

consumer = KafkaConsumer(
    "alert-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    enable_auto_commit=True,
    group_id="alert-worker",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Alert Worker Started")
send_log("🚀 Alert Worker Started", None)

print("Waiting for Kafka messages...")


# -------------------- MAIN LOOP --------------------

for message in consumer:

    event = message.value
    scan_id = event.get("scan_id")

    # =====================================================
    # 🔥 HYBRID CONTROL (INSTANT + DB)
    # =====================================================

    # ⚡ 1. INSTANT MEMORY CHECK (FASTEST)
    if is_stopped(scan_id):
        logger.info(f"⛔ Hard stop detected → {scan_id}")
        continue

    if is_paused(scan_id):
        time.sleep(2)
        continue

    # ⚡ 2. DB FALLBACK CHECK
    status = check_scan_control(scan_id)

    if status == "paused":
        time.sleep(2)
        continue

    if status == "stopped":
        logger.info(f"⛔ Scan stopped → {scan_id}")
        continue

    # =====================================================

    try:

        if event.get("event_type") != "alert":
            continue

        asset = event.get("asset")
        severity = event.get("severity", "UNKNOWN")
        message_text = event.get("message", "")

        # =====================================================
        # 🔥 CHECK BEFORE PROCESSING (CRITICAL)
        # =====================================================
        if is_stopped(scan_id):
            logger.info(f"⛔ Stopped before processing alert → {scan_id}")
            continue

        # =====================================================

        # ✅ SAVE CHECKPOINT BEFORE PROCESSING
        save_checkpoint(
            scan_id=scan_id,
            stage="alert_processing",
            last_asset=asset,
            last_event="alert",
            meta={
                "severity": severity
            }
        )

        log_msg = f"🚨 ALERT [{severity}] → {asset} | {message_text}"

        logger.warning(log_msg)
        send_log(log_msg, scan_id)

        db: Session = SessionLocal()

        try:

            # =====================================================
            # 🔥 CHECK BEFORE DB WORK (VERY IMPORTANT)
            # =====================================================
            if is_stopped(scan_id):
                logger.info(f"⛔ Stopped before DB insert → {scan_id}")
                continue

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if not asset_record:
                warn_msg = f"⚠️ Asset not found → {asset}"
                logger.warning(warn_msg)
                send_log(warn_msg, scan_id)
                continue

            # =====================================================
            # 🔥 FINAL CHECK BEFORE WRITE
            # =====================================================
            if is_stopped(scan_id):
                logger.info(f"⛔ Stopped before alert save → {scan_id}")
                continue

            alert = Alert(
                asset_id=asset_record.id,
                severity=severity,
                alert_type="security",
                description=message_text,
                created_at=datetime.now(UTC)
            )

            db.add(alert)
            db.commit()

            success_msg = f"✅ Alert stored → {asset}"
            logger.info(success_msg)
            send_log(success_msg, scan_id)

        except Exception as e:

            db.rollback()

            error_msg = f"❌ Failed to store alert → {str(e)}"
            logger.error(error_msg)
            send_log(error_msg, scan_id)

        finally:
            db.close()

    except Exception as e:

        crash_msg = f"💥 Alert worker crashed → {str(e)}"
        logger.error(crash_msg)
        send_log(crash_msg, scan_id)