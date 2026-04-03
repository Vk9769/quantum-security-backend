import json
import logging

from kafka import KafkaConsumer
from app.services.graph_service import GraphService
from app.workers.kafka_producer import send_event  # 🔥 IMPORTANT

# ✅ NEW IMPORTS (added)
from app.db.postgres import SessionLocal
from app.models.scan_jobs import ScanJob


# -------------------- INIT --------------------

graph = GraphService()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)

logger = logging.getLogger("ScanWorker")


# -------------------- KAFKA CONSUMER --------------------

consumer = KafkaConsumer(
    "scan-events",
    "asset-events",
    "port-scan-events",
    "tls-events",
    "certificate-events",
    "cbom-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="scan-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Scan Worker Started")
print("Waiting for Kafka messages...")


# -------------------- HELPERS --------------------

def extract_domain(hostname):
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


# 🔥 SEND LOG TO UI VIA KAFKA (IMPORTANT)
def send_log(message: str, scan_id=None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# ✅ NEW FUNCTION (SCAN CONTROL)
def is_scan_active(scan_id):
    if not scan_id:
        return True

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


# -------------------- MAIN LOOP --------------------

for message in consumer:

    try:

        event = message.value
        event_type = event.get("event_type")

        # ✅ NEW CONTROL LOGIC
        scan_id = event.get("scan_id")
        status = is_scan_active(scan_id)

        if status == "paused":
            logger.info(f"⏸ Scan paused → {scan_id}")
            continue

        if status is False:
            logger.info(f"⛔ Scan stopped → {scan_id}")
            continue

        logger.info(f"📩 Event received → {event_type}")

        # ============================================
        # SCAN START
        # ============================================
        if event_type == "scan_started":

            domain = event["domain"]

            logger.info(f"🔍 Scan started for {domain}")
            send_log(f"🔍 Scan started for {domain}", scan_id)

            graph.create_domain(domain)


        # ============================================
        # ASSET DISCOVERY
        # ============================================
        elif event_type == "asset_discovered":

            asset = event["asset"]
            domain = event.get("domain") or extract_domain(asset)

            logger.info(f"🌐 Asset discovered → {asset}")
            send_log(f"🌐 Asset discovered → {asset}", scan_id)

            graph.create_domain(domain)
            graph.create_asset(domain, asset)


        # ============================================
        # PORT SCAN
        # ============================================
        elif event_type == "port_open":

            asset = event["asset"]
            port = event["port"]

            logger.info(f"🔓 Open port → {asset}:{port}")
            send_log(f"🔓 Port open → {asset}:{port}", scan_id)

            graph.add_port(asset, port)


        # ============================================
        # TLS SCAN
        # ============================================
        elif event_type == "tls_scan_result":

            asset = event["asset"]

            logger.info(
                f"🔐 TLS → {asset} {event['tls_version']} {event['cipher_suite']}"
            )

            send_log(
                f"🔐 TLS → {asset} ({event['tls_version']})",
                scan_id
            )

            graph.add_tls(
                asset,
                event["tls_version"],
                event["cipher_suite"]
            )


        # ============================================
        # CERTIFICATE
        # ============================================
        elif event_type == "certificate_discovered":

            asset = event["asset"]

            logger.info(
                f"📜 Certificate → {asset} Issuer={event['issuer']}"
            )

            send_log(
                f"📜 Certificate → {asset} (Issuer: {event['issuer']})",
                scan_id
            )

            graph.add_certificate(
                asset,
                event["issuer"],
                event["subject"],
                event["expiry"],
                event["signature_algorithm"],
                event["key_size"]
            )


        # ============================================
        # CBOM
        # ============================================
        elif event_type == "cbom_generated":

            asset = event["asset"]

            logger.info(
                f"🧾 CBOM → {asset} Algo={event['signature_algorithm']}"
            )

            send_log(
                f"🧾 CBOM → {asset}",
                scan_id
            )

            graph.add_cbom(
                asset,
                event.get("signature_algorithm"),
                event.get("key_size"),
                event.get("expiry")
            )


        # ============================================
        # UNKNOWN EVENT
        # ============================================
        else:
            logger.warning(f"⚠️ Unknown event type: {event_type}")
            send_log(f"⚠️ Unknown event: {event_type}", scan_id)


    except Exception as e:

        logger.error("❌ Scan worker crashed")
        logger.error(e)

        send_log("❌ Scan worker error")