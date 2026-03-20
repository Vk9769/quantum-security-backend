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

    event = EventStream(
        event_type=event_type,
        payload=payload,
        created_at=datetime.now(UTC)
    )

    db.add(event)
    db.commit()


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


for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)
    event = message.value
    topic = message.topic
    event_type = event.get("event_type")

    db: Session = SessionLocal()

    try:

        # ------------------------------------
        # Store every event in event_stream
        # ------------------------------------
        scan_id = event.get("scan_id")
        store_event_stream(db, event_type, event)

        # ------------------------------------
        # Scan Started
        # ------------------------------------

        if event_type == "scan_started":

            domain = event["domain"]
            scan_id = event["scan_id"]

            # ✅ DO NOT CREATE AGAIN (already created in API)

            store_scan_event(
                db,
                scan_id,
                "scan_started",
                event
            )

            logger.info(f"Scan started → {domain}")
            send_log(f"🚀 Scan started → {domain}", scan_id)

        # ------------------------------------
        # Asset Discovered
        # ------------------------------------

        elif event_type == "asset_discovered":

            if not scan_id:
                continue

            store_scan_event(
                db,
                scan_id,
                "asset_discovered",
                event
            )

            logger.info(f"Asset discovered → {event['asset']}")
            send_log(f"🌐 Asset discovered → {event['asset']}", scan_id)
            
            
            
        elif event_type == "fingerprint_completed":

            if not scan_id:
                logger.warning("Skipping fingerprint event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "fingerprint_completed",
                event
            )

            logger.info(f"Fingerprint completed → {event['asset']}")
            send_log(f"🛰 Infra fingerprint completed → {event['asset']}", scan_id)

        # ------------------------------------
        # Port Scan
        # ------------------------------------

        elif event_type == "port_open":

            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "port_open",
                event
            )

            logger.info(
                f"Port discovered → {event['asset']}:{event['port']}"
            )
            send_log(f"🔓 Port open → {event['asset']}:{event['port']}", scan_id)

        # ------------------------------------
        # TLS Scan
        # ------------------------------------

        elif event_type == "tls_scan_result":
            
            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "tls_scan",
                event
            )

            logger.info(
                f"TLS scan → {event['asset']} {event['tls_version']}"
            )
            send_log(f"🔐 TLS detected → {event['asset']} {event['tls_version']}", scan_id)

        # ------------------------------------
        # Certificate
        # ------------------------------------

        elif event_type == "certificate_discovered":
            
            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "certificate_scan",
                event
            )

            logger.info(
                f"Certificate → {event['asset']}"
            )
            send_log(f"📜 Certificate discovered → {event['asset']}", scan_id)

        # ------------------------------------
        # CBOM Generated
        # ------------------------------------

        elif event_type == "cbom_generated":
            
            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "cbom_generated",
                event
            )

            logger.info(
                f"CBOM generated → {event['asset']}"
            )
            send_log(f"📦 CBOM generated → {event['asset']}", scan_id)

        # ------------------------------------
        # Risk Analysis
        # ------------------------------------

        elif topic == "vulnerability-events":
            
            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue


            store_scan_event(
                db,
                scan_id,
                "vulnerability_detected",
                event
            )

            logger.info(
                f"Vulnerability → {event['asset']} {event['cve']}"
            )
            send_log(f"⚠ Vulnerability → {event['asset']} {event['cve']}", scan_id)

        # ------------------------------------
        # Alerts
        # ------------------------------------

        elif topic == "alert-events":
            
            if not scan_id:
                logger.warning("Skipping event because scan_id not initialized")
                continue

            store_scan_event(
                db,
                scan_id,
                "alert_triggered",
                event
            )

            logger.info(
                f"Alert → {event['asset']} {event['severity']}"
            )
            send_log(f"🚨 Alert → {event['asset']} {event['severity']}", scan_id)

            # ✅ FINAL COMPLETION (CORRECT PLACE)
            finish_scan_job(db, scan_id)

            logger.info(f"✅ Scan completed → {scan_id}")
            send_log("✅ Scan completed", scan_id)

    except Exception as e:

        logger.error("Orchestrator error")
        logger.error(e)

    finally:

        db.close()
        