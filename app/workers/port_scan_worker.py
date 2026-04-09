import json
import logging
import time

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.services.scan_service import store_port_scan_result
from app.services.graph_service import GraphService
from app.workers.kafka_producer import send_event

# ✅ CONTROL
from app.utils.scan_control import check_scan_control

# ✅ CHECKPOINT
from app.utils.checkpoint import save_checkpoint, get_checkpoint


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


def ensure_asset_exists(db: Session, asset_identifier: str, organization_id: str = None):
    asset_identifier = normalize_asset(asset_identifier)

    if not asset_identifier:
        return None

    asset = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset_identifier
    ).first()

    if asset:
        return asset

    if not organization_id:
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

    logger.info(f"✅ Asset created → {asset_identifier}")
    return asset


# -------------------- INIT --------------------
graph = GraphService()
scanned_assets = set()

consumer = KafkaConsumer(
    "asset-events",
    "port-scan-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="port-scan-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Port Scan Worker Started")
print("Waiting for Kafka messages...")


# -------------------- CONTROL HELPER --------------------
def wait_if_paused(scan_id):
    while True:
        status = check_scan_control(scan_id)

        if status == "stopped":
            return "stopped"

        if status == "paused":
            time.sleep(2)
            continue

        return "running"


# -------------------- MAIN LOOP --------------------
for message in consumer:
    event = message.value
    print("KAFKA MESSAGE RECEIVED:", event)

    scan_id = event.get("scan_id")

    # 🔥 GLOBAL CONTROL (INSTANT)
    status = wait_if_paused(scan_id)

    if status == "stopped":
        logger.info(f"⛔ Hard stop → {scan_id}")
        continue

    event_type = event.get("event_type")

    # =====================================================
    # 🔥 DOMAIN LEVEL TRIGGER
    # =====================================================
    if event_type == "port_scan_requested":

        domain = normalize_asset(event.get("domain"))
        organization_id = event.get("organization_id")

        logger.info(f"🚀 Starting full port scan → {domain}")
        send_log(f"🚀 Starting port scan → {domain}", scan_id)

        db = SessionLocal()

        try:
            assets = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier.like(f"%{domain}")
            ).all()
        finally:
            db.close()

        if not assets:
            logger.warning(f"⚠ No assets found for domain → {domain}")
            send_log(f"⚠ No assets found for port scan → {domain}", scan_id)
            continue

        for a in assets:

            status = wait_if_paused(scan_id)
            if status == "stopped":
                break

            asset = normalize_asset(a.asset_identifier)

            if not asset:
                continue

            checkpoint = get_checkpoint(scan_id)
            resume_asset = checkpoint.get("last_asset") if checkpoint else None

            if resume_asset and asset != resume_asset:
                continue

            key = f"{asset}:{scan_id}"

            if key in scanned_assets:
                continue

            scanned_assets.add(key)

            send_log(f"🔍 Preparing port scan → {asset}", scan_id)

            db = SessionLocal()

            try:
                asset_record = ensure_asset_exists(db, asset, organization_id)

                if not asset_record:
                    continue

                send_log(f"🔍 Scanning ports → {asset}", scan_id)

                # 🔥 CRITICAL FIX: INTERRUPTIBLE PORT SCAN
                ports = []
                try:
                    for port in scan_ports(asset):

                        status = wait_if_paused(scan_id)
                        if status == "stopped":
                            logger.info(f"⛔ Stopped during port scan → {asset}")
                            break

                        ports.append(port)

                except Exception:
                    send_log(f"❌ Port scan failed → {asset}", scan_id)
                    continue

                for port in ports:

                    status = wait_if_paused(scan_id)
                    if status == "stopped":
                        break

                    checkpoint = get_checkpoint(scan_id)
                    resume_port = checkpoint.get("meta", {}).get("port") if checkpoint else None

                    if resume_port and port != resume_port:
                        continue

                    save_checkpoint(
                        scan_id,
                        stage="port_scan",
                        last_asset=asset,
                        meta={"port": port}
                    )

                    try:
                        store_port_scan_result(db, asset, port)
                        graph.add_port(asset, port)

                        send_event("port-scan-events", {
                            "scan_id": scan_id,
                            "organization_id": organization_id,
                            "event_type": "port_open",
                            "asset": asset,
                            "port": port
                        })

                        send_log(f"🔓 Open port → {asset}:{port}", scan_id)

                    except Exception as e:
                        logger.error(e)

                send_log(f"✅ Port scan completed → {asset}", scan_id)

            except Exception as e:
                db.rollback()
                logger.error(e)

            finally:
                db.close()

        continue


    # =====================================================
    # EXISTING FLOW
    # =====================================================
    if event_type != "asset_discovered":
        continue

    asset = normalize_asset(event.get("asset"))
    organization_id = event.get("organization_id")

    if not asset:
        continue

    key = f"{asset}:{scan_id}"

    if key in scanned_assets:
        continue

    scanned_assets.add(key)

    send_log(f"🔍 Preparing port scan → {asset}", scan_id)

    db = SessionLocal()

    try:
        asset_record = None

        for _ in range(5):

            status = wait_if_paused(scan_id)
            if status == "stopped":
                break

            asset_record = ensure_asset_exists(db, asset, organization_id)

            if asset_record:
                break

            time.sleep(1)

        if not asset_record:
            continue

        send_log(f"🔍 Scanning ports → {asset}", scan_id)

        # 🔥 INTERRUPTIBLE PORT SCAN
        ports = []
        try:
            for port in scan_ports(asset):

                status = wait_if_paused(scan_id)
                if status == "stopped":
                    logger.info(f"⛔ Stopped during port scan → {asset}")
                    break

                ports.append(port)

        except Exception:
            send_log(f"❌ Port scan failed → {asset}", scan_id)
            continue

        for port in ports:

            status = wait_if_paused(scan_id)
            if status == "stopped":
                break

            save_checkpoint(
                scan_id,
                stage="port_scan",
                last_asset=asset,
                meta={"port": port}
            )

            try:
                store_port_scan_result(db, asset, port)

                try:
                    graph.add_port(asset, port)
                except Exception:
                    pass

                send_event("port-scan-events", {
                    "scan_id": scan_id,
                    "organization_id": organization_id,
                    "event_type": "port_open",
                    "asset": asset,
                    "port": port
                })

                send_log(f"🔓 Open port → {asset}:{port}", scan_id)

            except Exception as e:
                logger.error(e)

        send_log(f"✅ Port scan completed → {asset}", scan_id)

    except Exception as e:
        db.rollback()
        logger.error(e)
        send_log(f"❌ Port scan crashed → {asset}", scan_id)

    finally:
        db.close()