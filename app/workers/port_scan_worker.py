import json
import logging
import time

from kafka import KafkaConsumer, KafkaProducer

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.services.scan_service import store_port_scan_result

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("PortScanWorker")

scanned_assets = set()

consumer = KafkaConsumer(
    "asset-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    group_id="port-scan-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

logger.info("Port Scan Worker Started")

print("Waiting for Kafka messages...")

for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    event = message.value

    if event.get("event_type") != "asset_discovered":
        continue

    asset = event["asset"]
    scan_id = event.get("scan_id")

    # prevent duplicate scanning
    if asset in scanned_assets:
        continue

    scanned_assets.add(asset)

    # wait for asset to be stored
    time.sleep(1)

    logger.info(f"Scanning ports → {asset}")

    ports = scan_ports(asset)

    db = SessionLocal()

    try:

        for port in ports:

            store_port_scan_result(db, asset, port)

            port_event = {
                "scan_id": scan_id,
                "event_type": "port_open",
                "asset": asset,
                "port": port
            }

            producer.send("port-scan-events", port_event)
            producer.flush()

            logger.info(f"Port event sent → {asset}:{port}")

    except Exception as e:

        logger.error("Port scan worker crashed")
        logger.error(e)

    finally:

        db.close()