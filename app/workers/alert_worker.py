import json
import logging
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
from datetime import datetime, UTC

from app.db.postgres import SessionLocal
from app.models.alert import Alert
from app.models.asset_registry import AssetRegistry
from app.workers.kafka_producer import send_event  # 🔥 IMPORTANT


# -------------------- LOGGING --------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)

logger = logging.getLogger("AlertWorker")


# -------------------- SEND LOG TO UI --------------------

def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- KAFKA CONSUMER --------------------

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

    try:

        if event.get("event_type") != "alert":
            continue

        asset = event.get("asset")
        severity = event.get("severity", "UNKNOWN")
        message_text = event.get("message", "")

        log_msg = f"🚨 ALERT [{severity}] → {asset} | {message_text}"

        logger.warning(log_msg)
        send_log(log_msg, scan_id)

        db: Session = SessionLocal()

        try:

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if not asset_record:
                warn_msg = f"⚠️ Asset not found → {asset}"
                logger.warning(warn_msg)
                send_log(warn_msg, scan_id)
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