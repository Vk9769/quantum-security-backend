import json
import logging
import time
import threading

from kafka import KafkaConsumer
from sqlalchemy.orm import Session

from app.scanners.port_scanner import scan_ports
from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.services.scan_service import store_port_scan_result
from app.services.graph_service import GraphService
from app.workers.kafka_producer import send_event

from app.utils.scan_control import check_scan_control
from app.utils.checkpoint import save_checkpoint, get_checkpoint


# -------------------- LOGGING --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("PortScanWorker")


# -------------------- GLOBAL CONTROL --------------------
active_scans = set()
lock = threading.Lock()

MAX_THREADS = 5
semaphore = threading.Semaphore(MAX_THREADS)


# -------------------- HELPERS --------------------
def send_log(message: str, scan_id: str = None, progress=None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id,
        "progress": progress
    })


def send_progress(asset, scan_id, percent, current, total):
    send_event("scan-logs", {
        "type": "progress",
        "scan_id": scan_id,
        "asset": asset,
        "progress_percent": percent,
        "current": current,
        "total": total
    })


def print_progress_bar(current, total, length=20):
    if total == 0:
        return "[░░░░░░░░░░░░░░░░░░░░] 0%"
    percent = int((current / total) * 100)
    filled = int(length * current // total)
    bar = "█" * filled + "░" * (length - filled)
    return f"[{bar}] {percent}% ({current}/{total})"


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

    group_id="port-scan-worker-v2",

    enable_auto_commit=True,

    max_poll_interval_ms=600000,
    session_timeout_ms=30000,
    heartbeat_interval_ms=10000,

    max_poll_records=1,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Port Scan Worker Started")
print("Waiting for Kafka messages...")


# -------------------- CONTROL --------------------
def wait_if_paused(scan_id):
    while True:
        status = check_scan_control(scan_id)

        if status == "stopped":
            return "stopped"

        if status == "paused":
            time.sleep(2)
            continue

        return "running"


# -------------------- 🔥 THREAD SCAN FUNCTION --------------------
def run_port_scan(asset, scan_id, organization_id):
    key = f"{asset}:{scan_id}"

    with semaphore:
        db = SessionLocal()

        try:
            send_log(f"🔍 Scanning ports → {asset}", scan_id)

            ports = []
            try:
                for port in scan_ports(asset):
                    status = wait_if_paused(scan_id)
                    if status == "stopped":
                        return
                    ports.append(port)

            except Exception:
                send_log(f"❌ Port scan failed → {asset}", scan_id)
                return

            total = len(ports)
            open_count = 0

            for i, port in enumerate(ports, start=1):

                status = wait_if_paused(scan_id)
                if status == "stopped":
                    break

                percent = int((i / total) * 100) if total else 0

                progress_bar = print_progress_bar(i, total)
                logger.info(f"{asset} {progress_bar}")

                send_progress(asset, scan_id, percent, i, total)

                save_checkpoint(
                    scan_id,
                    stage="port_scan",
                    last_asset=asset,
                    meta={"port": port}
                )

                try:
                    store_port_scan_result(db, asset, port)
                    graph.add_port(asset, port)

                    open_count += 1

                    send_event("port-scan-events", {
                        "scan_id": scan_id,
                        "organization_id": organization_id,
                        "event_type": "port_open",
                        "asset": asset,
                        "port": port
                    })

                    send_log(f"🔓 Open port → {asset}:{port}", scan_id, percent)

                except Exception as e:
                    logger.error(e)

            send_log(
                f"✅ Port scan completed → {asset} | Open Ports: {open_count}/{total}",
                scan_id,
                100
            )

            # ✅ FIX: Trigger TLS ONLY if port 443 exists
            if 443 in ports:
                send_event("tls-events", {
                    "event_type": "tls_scan_requested",
                    "scan_id": scan_id,
                    "organization_id": organization_id,
                    "asset": asset
                })
                logger.info(f"🚀 TLS scan triggered → {asset}")
            else:
                logger.warning(f"⚠ Skipping TLS → No HTTPS port → {asset}")

            # OPTIONAL (unchanged)
            send_event("service-events", {
                "event_type": "service_scan_requested",
                "scan_id": scan_id,
                "organization_id": organization_id,
                "asset": asset,
                "ports": ports
            })

            logger.info(f"🚀 Service detection triggered → {asset}")

        finally:
            db.close()

            with lock:
                active_scans.discard(key)


# -------------------- MAIN LOOP --------------------
for message in consumer:
    event = message.value
    print("KAFKA MESSAGE RECEIVED:", event)

    scan_id = event.get("scan_id")

    status = wait_if_paused(scan_id)
    if status == "stopped":
        continue

    event_type = event.get("event_type")

    if event_type == "port_scan_requested":

        domain = normalize_asset(event.get("domain"))
        organization_id = event.get("organization_id")

        send_log(f"🚀 Starting port scan → {domain}", scan_id)

        db = SessionLocal()

        try:
            assets = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier.like(f"%{domain}")
            ).all()
        finally:
            db.close()

        for a in assets:
            asset = normalize_asset(a.asset_identifier)
            key = f"{asset}:{scan_id}"

            with lock:
                if key in active_scans:
                    logger.warning(f"⚠ Duplicate scan skipped → {key}")
                    continue
                active_scans.add(key)

            threading.Thread(
                target=run_port_scan,
                args=(asset, scan_id, organization_id),
                daemon=True
            ).start()

        continue

    if event_type != "asset_discovered":
        continue

    asset = normalize_asset(event.get("asset"))
    organization_id = event.get("organization_id")

    key = f"{asset}:{scan_id}"

    with lock:
        if key in active_scans:
            logger.warning(f"⚠ Duplicate scan skipped → {key}")
            continue
        active_scans.add(key)

    threading.Thread(
        target=run_port_scan,
        args=(asset, scan_id, organization_id),
        daemon=True
    ).start()