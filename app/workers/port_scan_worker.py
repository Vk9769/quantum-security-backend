import json
import logging
from kafka import KafkaConsumer, KafkaProducer

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.services.scan_service import store_port_scan_result

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PortScanWorker")

consumer = KafkaConsumer(
    "asset-events",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    group_id=None,
    enable_auto_commit=False,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers="127.0.0.1:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

logger.info("Port Scan Worker Started")

db = SessionLocal()

for message in consumer:

    event = message.value

    asset = event["asset"]

    logger.info(f"Scanning ports → {asset}")

    ports = scan_ports(asset)

    for port in ports:

        # store in postgres
        store_port_scan_result(db, asset, port)

        # send kafka event
        port_event = {
            "event_type": "port_open",
            "asset": asset,
            "port": port
        }

        producer.send("port-scan-events", port_event)

        logger.info(f"Port event sent → {asset}:{port}")

db.close()