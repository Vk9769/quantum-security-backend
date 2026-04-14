import json
import logging
import time

from kafka import KafkaConsumer
from app.services.graph_service import GraphService
from app.workers.kafka_producer import send_event

# ✅ SCAN CONTROL
from app.utils.scan_control import check_scan_control

# ✅ CHECKPOINT IMPORT
from app.utils.checkpoint import save_checkpoint, get_checkpoint


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
# ✅ fingerprint-events REMOVED

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


def send_log(message: str, scan_id=None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- MAIN LOOP --------------------

for message in consumer:
    try:
        event = message.value
        event_type = event.get("event_type")
        scan_id = event.get("scan_id")

        # ==================================================
        # 🔥 GLOBAL CONTROL LOOP (STRONG FIX)
        # ==================================================
        while True:
            status = check_scan_control(scan_id)

            if status == "paused":
                logger.info(f"⏸ Scan paused → {scan_id}")
                time.sleep(2)
                continue

            if status == "stopped":
                logger.info(f"⛔ Hard stop → {scan_id}")
                break

            break

        if status == "stopped":
            continue  # ❗ skip entire event immediately

        # ==================================================
        # CHECKPOINT LOAD
        # ==================================================
        checkpoint = get_checkpoint(scan_id) or {}
        last_stage = checkpoint.get("stage")
        last_asset = checkpoint.get("last_asset")

        logger.info(f"📩 Event received → {event_type}")

        # ============================================
        # SCAN START
        # ============================================
        if event_type == "scan_started":

            save_checkpoint(scan_id, "scan_started")

            domain = event["domain"]

            logger.info(f"🔍 Scan started for {domain}")
            send_log(f"🔍 Scan started for {domain}", scan_id)

            graph.create_domain(domain)

        # ============================================
        # ASSET DISCOVERY
        # ============================================
        elif event_type == "asset_discovered":

            # 🔥 RESUME SAFETY
            if last_stage == "asset_discovered" and last_asset:
                if event["asset"] != last_asset:
                    continue
                else:
                    last_asset = None

            asset = event["asset"]
            domain = event.get("domain") or extract_domain(asset)

            save_checkpoint(
                scan_id,
                stage="asset_discovered",
                last_asset=asset
            )

            logger.info(f"🌐 Asset discovered → {asset}")
            send_log(f"🌐 Asset discovered → {asset}", scan_id)

            graph.create_domain(domain)
            graph.create_asset(domain, asset)

        # ============================================
        # PORT SCAN TRIGGER
        # ============================================
        elif event_type == "port_scan_requested":

            domain = event.get("domain")

            logger.info(f"🚀 Port scan requested → {domain}")
            send_log(f"🚀 Starting port scan → {domain}", scan_id)

        # ============================================
        # PORT OPEN
        # ============================================
        elif event_type == "port_open":

            asset = event["asset"]
            port = event["port"]

            # 🔥 MID-CHECK (IMPORTANT)
            if check_scan_control(scan_id) == "stopped":
                logger.info(f"⛔ Stopped before processing port → {scan_id}")
                continue

            save_checkpoint(
                scan_id,
                stage="port_open",
                last_asset=asset,
                meta={"port": port}
            )

            logger.info(f"🔓 Open port → {asset}:{port}")
            send_log(f"🔓 Port open → {asset}:{port}", scan_id)

            graph.add_port(asset, port)

        # ============================================
        # TLS
        # ============================================
        elif event_type == "tls_scan_result":

            asset = event["asset"]

            if check_scan_control(scan_id) == "stopped":
                logger.info(f"⛔ Stopped before TLS → {scan_id}")
                continue

            save_checkpoint(
                scan_id,
                stage="tls_scan",
                last_asset=asset
            )

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

            if check_scan_control(scan_id) == "stopped":
                logger.info(f"⛔ Stopped before certificate → {scan_id}")
                continue

            save_checkpoint(
                scan_id,
                stage="certificate",
                last_asset=asset
            )

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

            if check_scan_control(scan_id) == "stopped":
                logger.info(f"⛔ Stopped before CBOM → {scan_id}")
                continue

            save_checkpoint(
                scan_id,
                stage="cbom",
                last_asset=asset
            )

            logger.info(
                f"🧾 CBOM → {asset} Algo={event['signature_algorithm']}"
            )

            send_log(f"🧾 CBOM → {asset}", scan_id)

            graph.add_cbom(
                asset,
                event.get("signature_algorithm"),
                event.get("key_size"),
                event.get("expiry")
            )

        # ============================================
        # IGNORE OLD EVENT
        # ============================================
        elif event_type == "start_port_scan":
            continue

        # ============================================
        # UNKNOWN
        # ============================================
        else:
            logger.warning(f"⚠️ Unknown event type: {event_type}")

    except Exception as e:
        logger.error("❌ Scan worker crashed")
        logger.error(e)

        send_log("❌ Scan worker error")