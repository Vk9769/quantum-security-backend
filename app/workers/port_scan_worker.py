import json
import logging
import time
import asyncio

from kafka import KafkaConsumer, KafkaProducer

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.services.scan_service import store_port_scan_result
from app.services.graph_service import GraphService
from app.workers.kafka_producer import send_event


# -------------------- LOGGING --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("PortScanWorker")


def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })

# -------------------- INIT --------------------
graph = GraphService()
scanned_assets = set()

consumer = KafkaConsumer(
    "asset-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="port-scan-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

logger.info("🚀 Port Scan Worker Started")
print("Waiting for Kafka messages...")

# -------------------- MAIN LOOP --------------------

for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    event = message.value

    if event.get("event_type") != "asset_discovered":
        continue

    asset = event.get("asset")
    scan_id = event.get("scan_id")

    if not asset:
        continue

    # prevent duplicate scanning
    if asset in scanned_assets:
        continue

    scanned_assets.add(asset)

    # wait for DB consistency
    time.sleep(1)

    logger.info(f"🔍 Scanning ports → {asset}")
    send_log(f"🔍 Scanning ports → {asset}", scan_id)

    try:
        ports = scan_ports(asset)

    except Exception as e:
        logger.error(f"Port scanner failed for {asset}: {e}")
        send_log(f"❌ Port scan failed → {asset}", scan_id)
        continue

    db = SessionLocal()

    try:

        for port in ports:

            try:
                # ---------------- STORE IN POSTGRES ----------------
                store_port_scan_result(db, asset, port)

                # ---------------- GRAPH (NEO4J) ----------------
                graph.add_port(asset, port)

                # ---------------- KAFKA EVENT ----------------
                port_event = {
                    "scan_id": scan_id,
                    "event_type": "port_open",
                    "asset": asset,
                    "port": port
                }

                producer.send("port-scan-events", port_event)

                send_log(f"🔓 Open port → {asset}:{port}", scan_id)
                
                logger.info(f"✅ Port event sent → {asset}:{port}")

            except Exception as e:
                logger.error(f"Error processing port {port} for {asset}: {e}")

        producer.flush()
        db.commit()

        logger.info(f"✅ Port scan completed → {asset}")
        send_log(f"✅ Port scan completed → {asset}", scan_id)

    except Exception as e:

        db.rollback()

        logger.error("❌ Port scan worker crashed")
        logger.error(e)

        send_log(f"❌ Port scan crashed → {asset}", scan_id)
        
    finally:
        db.close()