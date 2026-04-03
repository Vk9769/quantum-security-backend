import json
import logging
from datetime import datetime
from kafka import KafkaConsumer
from sqlalchemy.orm import Session
from datetime import datetime, UTC
from app.db.postgres import SessionLocal
from app.models.scan_jobs import ScanJob
from app.models.scan_events import ScanEvent
from app.models.event_stream import EventStream

from app.models.scan_deltas import ScanDelta
from app.models.asset_registry import AssetRegistry


# ✅ FIXED SCAN CONTROL FUNCTION
def is_scan_active(scan_id):
    if not scan_id:
        return False  # 🔥 FIX: do NOT allow processing without scan_id

    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            return False

        if scan.status == "paused":
            return "paused"

        if scan.status == "stopped":
            return False

        return True

    finally:
        db.close()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("OrchestratorWorker")

from app.utils.log_streamer import setup_logger
setup_logger()

from app.workers.kafka_producer import send_event


def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


consumer = KafkaConsumer(
    "scan-events",
    "asset-events",
    "port-scan-events",
    "tls-events",
    "certificate-events",
    "fingerprint-events",
    "cbom-events",
    "vulnerability-events",
    "alert-events",
    bootstrap_servers="localhost:9092",
    group_id="orchestrator-worker",
    auto_offset_reset="latest",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Orchestrator Worker Started")

print("Waiting for Kafka messages...")


def ensure_scan_job_exists(db, scan_id):

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id
    ).first()

    if job:
        return

    job = ScanJob(
        id=scan_id,
        organization_id="10024715-cd08-49a4-b316-4f394c14d267",
        scan_type="external_attack_surface",
        trigger="manual",
        status="running",
        started_at=datetime.now(UTC)
    )

    db.add(job)
    db.commit()

    logger.info(f"Recovered missing scan_job → {scan_id}")


def store_event_stream(db: Session, event_type: str, payload: dict):

    event_id = payload.get("event_id")

    if not event_id:
        logger.warning("⚠ Missing event_id, skipping event")
        return False

    existing = db.query(EventStream).filter(
        EventStream.event_type == event_type,
        EventStream.payload.contains({"event_id": event_id})
    ).first()

    if existing:
        logger.info(f"⚠ Duplicate event skipped → {event_id}")
        return False

    event = EventStream(
        event_type=event_type,
        payload=payload,
        created_at=datetime.now(UTC)
    )

    db.add(event)
    db.commit()

    return True


def store_scan_event(db: Session, scan_id, event_type: str, payload: dict):

    ensure_scan_job_exists(db, scan_id)

    scan_event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        event_data=payload,
        timestamp=datetime.now(UTC)
    )

    db.add(scan_event)
    db.commit()


def finish_scan_job(db: Session, scan_id):

    job = db.query(ScanJob).filter(
        ScanJob.id == scan_id
    ).first()

    if not job:
        return

    job.status = "completed"
    job.finished_at = datetime.now(UTC)

    db.commit()

    logger.info(f"Scan completed → {scan_id}")


def save_drift(db, asset_id, change_type, description):
    drift = ScanDelta(
        asset_id=asset_id,
        change_type=change_type,
        change_description=description
    )
    db.add(drift)
    db.commit()

    logger.info(f"🔥 Drift saved → {change_type}: {description}")


# ================= MAIN LOOP =================

for message in consumer:

    event = message.value
    topic = message.topic
    event_type = event.get("event_type")
    scan_id = event.get("scan_id")

    print("KAFKA MESSAGE RECEIVED:", event)

    # 🔥 FIX 1: HARD BLOCK if no scan_id
    if not scan_id:
        logger.warning("⚠ Missing scan_id → skipping event")
        continue

    # 🔥 FIX 2: CHECK SCAN STATE
    status = is_scan_active(scan_id)

    if status == "paused":
        logger.info(f"⏸ Scan paused → {scan_id}")
        continue

    if status is False:
        logger.info(f"⛔ Scan stopped → {scan_id}")
        continue

    db: Session = SessionLocal()

    try:

        # ------------------------------------
        # Store every event
        # ------------------------------------
        is_new = store_event_stream(db, event_type, event)

        if not is_new:
            continue

        # ------------------------------------
        # Scan Started
        # ------------------------------------
        if event_type == "scan_started":

            domain = event["domain"]

            store_scan_event(db, scan_id, "scan_started", event)

            logger.info(f"Scan started → {domain}")
            send_log(f"🚀 Scan started → {domain}", scan_id)

        # ------------------------------------
        # Asset Discovered
        # ------------------------------------
        elif event_type == "asset_discovered":

            asset = event["asset"]

            store_scan_event(db, scan_id, "asset_discovered", event)

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if asset_record:
                save_drift(db, asset_record.id, "New Asset", asset)

            logger.info(f"Asset discovered → {asset}")
            send_log(f"🌐 Asset discovered → {asset}", scan_id)

        # ------------------------------------
        # Fingerprint
        # ------------------------------------
        elif event_type == "fingerprint_completed":

            store_scan_event(db, scan_id, "fingerprint_completed", event)

            logger.info(f"Fingerprint completed → {event['asset']}")
            send_log(f"🛰 Infra fingerprint completed → {event['asset']}", scan_id)

        # ------------------------------------
        # Port Scan
        # ------------------------------------
        elif event_type == "port_open":

            asset = event["asset"]
            port = event["port"]

            store_scan_event(db, scan_id, "port_open", event)

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if asset_record:
                save_drift(db, asset_record.id, "New Open Port", f"{asset} → {port}")

            logger.info(f"Port discovered → {asset}:{port}")
            send_log(f"🔓 Port open → {asset}:{port}", scan_id)

        # ------------------------------------
        # TLS
        # ------------------------------------
        elif event_type == "tls_scan_result":

            asset = event["asset"]
            tls_version = event["tls_version"]

            store_scan_event(db, scan_id, "tls_scan", event)

            asset_record = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == asset
            ).first()

            if asset_record:
                save_drift(db, asset_record.id, "TLS Change", f"{asset} → {tls_version}")

            logger.info(f"TLS scan → {asset} {tls_version}")
            send_log(f"🔐 TLS detected → {asset} {tls_version}", scan_id)

        # ------------------------------------
        # Certificate
        # ------------------------------------
        elif event_type == "certificate_discovered":

            store_scan_event(db, scan_id, "certificate_scan", event)

            logger.info(f"Certificate → {event['asset']}")
            send_log(f"📜 Certificate discovered → {event['asset']}", scan_id)

        # ------------------------------------
        # CBOM
        # ------------------------------------
        elif event_type == "cbom_generated":

            store_scan_event(db, scan_id, "cbom_generated", event)

            logger.info(f"CBOM generated → {event['asset']}")
            send_log(f"📦 CBOM generated → {event['asset']}", scan_id)

        # ------------------------------------
        # Vulnerability
        # ------------------------------------
        elif topic == "vulnerability-events":

            store_scan_event(db, scan_id, "vulnerability_detected", event)

            logger.info(f"Vulnerability → {event['asset']} {event['cve']}")
            send_log(f"⚠ Vulnerability → {event['asset']} {event['cve']}", scan_id)

        # ------------------------------------
        # Alerts
        # ------------------------------------
        elif topic == "alert-events":

            store_scan_event(db, scan_id, "alert_triggered", event)

            logger.info(f"Alert → {event['asset']} {event['severity']}")
            send_log(f"🚨 Alert → {event['asset']} {event['severity']}", scan_id)

            finish_scan_job(db, scan_id)

            logger.info(f"✅ Scan completed → {scan_id}")
            send_log("✅ Scan completed", scan_id)

    except Exception as e:

        logger.error("Orchestrator error")
        logger.error(e)

    finally:
        db.close()