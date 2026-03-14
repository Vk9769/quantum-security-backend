import json
import logging
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.postgres import SessionLocal
from app.models.alert import Alert
from app.models.asset_registry import AssetRegistry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)

logger = logging.getLogger("AlertWorker")


consumer = KafkaConsumer(
    "alert-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    enable_auto_commit=True,
    group_id="alert-worker",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Alert Worker Started")

print("Waiting for Kafka messages...")

for message in consumer:

    event = message.value

    if event.get("event_type") != "alert":
        continue

    asset = event.get("asset")
    severity = event.get("severity", "UNKNOWN")
    message_text = event.get("message", "")

    logger.warning(f"🚨 ALERT [{severity}] → {asset} | {message_text}")

    db: Session = SessionLocal()

    try:

        asset_record = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset
        ).first()

        if not asset_record:
            logger.warning(f"Asset not found → {asset}")
            continue

        alert = Alert(
            asset_id=asset_record.id,
            severity=severity,
            alert_type="security",
            description=message_text,
            created_at=datetime.utcnow()
        )

        db.add(alert)
        db.commit()

        logger.info(f"Alert stored → {asset}")

    except Exception as e:

        db.rollback()
        logger.error("Failed to store alert")
        logger.error(e)

    finally:

        db.close()