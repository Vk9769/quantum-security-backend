import json
import logging
import time

from kafka import KafkaConsumer, KafkaProducer
from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.models.asset_fingerprint import AssetFingerprint
from app.scanners.infra_fingerprint import scan_infra_fingerprint
from app.services.asset_fingerprint_service import (
    save_asset_fingerprint,
    serialize_asset_fingerprint
)
from app.utils.log_streamer import setup_logger
from app.workers.kafka_producer import send_event

# ✅ UPDATED IMPORT (USE CENTRAL SCAN CONTROL)
from app.utils.scan_control import is_scan_active


# --------------------------------------------------
# LOG STREAM
# --------------------------------------------------
setup_logger()


def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def normalize_asset(asset: str) -> str:
    if not asset:
        return ""
    return asset.strip().lower().replace(" ", "")


# --------------------------------------------------
# LOGGING
# --------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("FingerprintWorker")


# --------------------------------------------------
# KAFKA
# --------------------------------------------------
consumer = KafkaConsumer(
    "asset-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="fingerprint-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Fingerprint Worker Started")
print("Waiting for Kafka messages...")


# --------------------------------------------------
# MAIN LOOP
# --------------------------------------------------
for message in consumer:
    print("KAFKA MESSAGE RECEIVED:", message.value)

    event = message.value
    scan_id = event.get("scan_id")

    # 🔥 SCAN CONTROL (NOW CENTRALIZED)
    status = is_scan_active(scan_id)

    if status == "paused":
        logger.info(f"⏸ Scan paused → {scan_id}")
        continue

    if status is False:
        logger.info(f"⛔ Scan stopped → {scan_id}")
        continue

    try:
        if event.get("event_type") != "asset_discovered":
            continue

        raw_asset = event.get("asset", "")
        raw_domain = event.get("domain", raw_asset)

        asset = normalize_asset(raw_asset)
        domain = normalize_asset(raw_domain)

        if not asset:
            continue

        logger.info(f"🛰 Infra fingerprint started → {asset}")
        send_log(f"🛰 Infra fingerprint started → {asset}", scan_id)

        # --------------------------------------------------
        # optional small wait for asset row consistency
        # --------------------------------------------------
        time.sleep(1)

        # --------------------------------------------------
        # RUN SCAN
        # --------------------------------------------------
        try:
            fingerprint_result = scan_infra_fingerprint(asset)
        except Exception as e:
            logger.error(f"Infra fingerprint scan failed → {asset}")
            logger.error(e)
            send_log(f"❌ Infra fingerprint scan failed → {asset}", scan_id)
            continue

        db: Session = SessionLocal()

        try:
            # --------------------------------------------------
            # FIND ASSET
            # --------------------------------------------------
            asset_record = None

            for _ in range(3):
                asset_record = db.query(AssetRegistry).filter(
                    AssetRegistry.asset_identifier.in_([asset, domain])
                ).first()

                if asset_record:
                    break

                logger.warning(f"Asset not found → {asset}, retrying...")
                time.sleep(2)

            if not asset_record:
                logger.warning(f"Asset still missing → {asset}")
                send_log(f"⚠ Asset not found for fingerprint → {asset}", scan_id)
                continue

            # --------------------------------------------------
            # SAVE FINGERPRINT
            # --------------------------------------------------
            saved = save_asset_fingerprint(
                db=db,
                asset_id=asset_record.id,
                fingerprint_data=fingerprint_result
            )

            if not saved:
                logger.warning(f"Fingerprint save failed → {asset}")
                send_log(f"❌ Fingerprint save failed → {asset}", scan_id)
                continue

            serialized = serialize_asset_fingerprint(saved)

            logger.info(
                f"✅ Fingerprint stored → {asset} | "
                f"hosting_provider={serialized.get('hosting_provider')} | "
                f"web_server={serialized.get('web_server')} | "
                f"framework={serialized.get('framework')} | "
                f"asn={serialized.get('asn')} | "
                f"org={serialized.get('org_name')}"
            )

            send_log(
                f"✅ Infra fingerprint stored → {asset} | "
                f"{serialized.get('hosting_provider') or serialized.get('org_name') or 'Unknown Provider'}",
                scan_id
            )

            # --------------------------------------------------
            # SEND NEXT EVENT
            # --------------------------------------------------
            fingerprint_event = {
                "scan_id": scan_id,
                "event_type": "fingerprint_completed",
                "asset": asset,
                "asset_id": str(asset_record.id),

                "hosting_provider": serialized.get("hosting_provider"),
                "cloud_provider": serialized.get("cloud_provider"),
                "region": serialized.get("region"),

                "web_server": serialized.get("web_server"),
                "web_server_detection_method": serialized.get("web_server_detection_method"),
                "web_server_candidates": serialized.get("web_server_candidates"),
                "passive_technology_matches": serialized.get("passive_technology_matches"),

                "backend_stack": serialized.get("backend_stack"),
                "framework": serialized.get("framework"),
                "cms": serialized.get("cms"),

                "waf_cdn": serialized.get("waf_cdn"),
                "dns_provider": serialized.get("dns_provider"),
                "email_provider": serialized.get("email_provider"),
                "load_balancer": serialized.get("load_balancer"),

                "os_hint": serialized.get("os_hint"),
                "deployment_type": serialized.get("deployment_type"),
                "reverse_dns": serialized.get("reverse_dns"),

                "asn": serialized.get("asn"),
                "org_name": serialized.get("org_name"),
                "confidence_score": serialized.get("confidence_score"),

                "favicon_hash": serialized.get("favicon_hash"),
                "behavioral_fingerprint": serialized.get("behavioral_fingerprint"),
                "external_exposure_summary": serialized.get("external_exposure_summary"),
                "evidence_summary": serialized.get("evidence_summary")
            }

            send_event("fingerprint-events", fingerprint_event, key=asset)

            logger.info(f"📤 Fingerprint event sent → {asset}")
            send_log(f"📤 Fingerprint event sent → {asset}", scan_id)

        except Exception as e:
            db.rollback()
            logger.error(f"❌ Fingerprint worker DB failed → {asset}")
            logger.error(e)
            send_log(f"❌ Fingerprint DB failed → {asset}", scan_id)

        finally:
            db.close()

    except Exception as e:
        logger.error("❌ Fingerprint worker crashed")
        logger.error(e)
        send_log(f"❌ Fingerprint worker crashed → {event.get('asset')}", scan_id)