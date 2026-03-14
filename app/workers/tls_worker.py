import json
import logging
from datetime import datetime
import time
from kafka import KafkaConsumer, KafkaProducer
from sqlalchemy.orm import Session

from app.scanners.tls_scanner import scan_tls
from app.db.postgres import SessionLocal
from app.models.tls import TLSScanResult
from app.models.asset_registry import AssetRegistry
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("TLSWorker")


consumer = KafkaConsumer(
    "asset-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    group_id="tls-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

logger.info("TLS Worker Started")

print("Waiting for Kafka messages...")
for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value

    asset = event["asset"]

    port = 443
 
    logger.info(f"Scanning TLS → {asset}")

    result = scan_tls(asset, port)

    if not result:
        continue

    db: Session = SessionLocal()

    try:

        asset_record = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset
        ).first()

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
            logger.warning(f"Asset still missing after retries → {asset}")
            continue

        existing = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == asset_record.id
        ).first()

        if existing:

            existing.tls_version = result["tls_version"]
            existing.cipher_suite = result["cipher_suite"]
            existing.key_exchange = result["key_exchange"]
            existing.scan_time = datetime.utcnow()

            logger.info(f"TLS updated → {asset}")

        else:

            tls_result = TLSScanResult(
                asset_id=asset_record.id,
                tls_version=result["tls_version"],
                cipher_suite=result["cipher_suite"],
                key_exchange=result["key_exchange"],
                forward_secrecy="DHE" in result["cipher_suite"],
                scan_time=datetime.utcnow()
            )

            db.add(tls_result)

            logger.info(f"TLS stored → {asset}")

        db.commit()

    except Exception as e:

        db.rollback()
        logger.error("Failed to store TLS result")
        logger.error(e)

    finally:
        db.close()

    # send kafka event for next pipeline
    tls_event = {
        "scan_id": event.get("scan_id"),
        "event_type": "tls_scan_result",
        "asset": asset,
        "tls_version": result["tls_version"],
        "cipher_suite": result["cipher_suite"],
        "key_exchange": result["key_exchange"]
    }

    producer.send("tls-events", tls_event)

    logger.info(f"TLS event sent → {asset}")