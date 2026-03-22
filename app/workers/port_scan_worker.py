import json
import logging
import time

from kafka import KafkaConsumer, KafkaProducer
from sqlalchemy.orm import Session

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
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


# -------------------- HELPERS --------------------
def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


def normalize_asset(value: str) -> str:
    if not value:
        return ""

    return (
        str(value).strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


def ensure_asset_exists(
    db: Session,
    asset_identifier: str,
    organization_id: str = None
):
    asset_identifier = normalize_asset(asset_identifier)

    if not asset_identifier:
        return None

    asset = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset_identifier
    ).first()

    if asset:
        return asset

    if not organization_id:
        logger.warning(f"Cannot create missing asset without organization_id → {asset_identifier}")
        return None

    asset = AssetRegistry(
        organization_id=organization_id,
        asset_identifier=asset_identifier,
        asset_type="subdomain",
        status="active"
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    logger.info(f"✅ Asset registry entry created in worker → {asset_identifier}")
    return asset


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

    asset = normalize_asset(event.get("asset"))
    scan_id = event.get("scan_id")
    organization_id = event.get("organization_id") or "10024715-cd08-49a4-b316-4f394c14d267"

    if not asset:
        logger.warning("Skipping asset_discovered event with empty asset")
        continue

    # prevent duplicate scanning
    if asset in scanned_assets:
        logger.info(f"Skipping duplicate asset scan → {asset}")
        continue

    scanned_assets.add(asset)

    logger.info(f"🔍 Preparing port scan → {asset}")
    send_log(f"🔍 Preparing port scan → {asset}", scan_id)

    db = SessionLocal()

    try:
        # ---------------- ENSURE ASSET EXISTS ----------------
        asset_record = None

        for attempt in range(5):
            asset_record = ensure_asset_exists(
                db,
                asset_identifier=asset,
                organization_id=organization_id
            )

            if asset_record:
                break

            logger.warning(f"Asset not ready → {asset}, retrying... ({attempt + 1}/5)")
            time.sleep(1)

        if not asset_record:
            logger.error(f"❌ Asset still missing before port scan → {asset}")
            send_log(f"❌ Asset not found before port scan → {asset}", scan_id)
            continue

        logger.info(f"✅ Asset ready for scan → {asset}")
        send_log(f"✅ Asset ready for scan → {asset}", scan_id)

        # small wait for consistency
        time.sleep(1)

        # ---------------- PORT SCAN ----------------
        logger.info(f"🔍 Scanning ports → {asset}")
        send_log(f"🔍 Scanning ports → {asset}", scan_id)

        try:
            ports = scan_ports(asset)
        except Exception as e:
            logger.error(f"Port scanner failed for {asset}: {e}")
            send_log(f"❌ Port scan failed → {asset}", scan_id)
            continue

        if not ports:
            logger.info(f"No open ports found → {asset}")
            send_log(f"ℹ No open ports found → {asset}", scan_id)
            continue

        for port in ports:
            try:
                # ---------------- STORE IN POSTGRES ----------------
                store_port_scan_result(db, asset, port)

                # ---------------- GRAPH (NEO4J) ----------------
                try:
                    graph.add_port(asset, port)
                except Exception as e:
                    logger.error(f"Graph update failed for {asset}:{port} → {e}")

                # ---------------- KAFKA EVENT ----------------
                port_event = {
                    "scan_id": scan_id,
                    "organization_id": organization_id,
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

        logger.info(f"✅ Port scan completed → {asset}")
        send_log(f"✅ Port scan completed → {asset}", scan_id)

    except Exception as e:
        db.rollback()
        logger.error("❌ Port scan worker crashed")
        logger.error(e)
        send_log(f"❌ Port scan crashed → {asset}", scan_id)

    finally:
        db.close()