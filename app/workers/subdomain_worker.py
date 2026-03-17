import json
import logging
from kafka import KafkaConsumer
from app.db.postgres import SessionLocal
from app.services.asset_service import store_subdomain
from app.scanners.subdomain_scanner import discover_subdomains
from app.workers.kafka_producer import send_asset_discovered
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)
logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("SubdomainWorker")

consumer = KafkaConsumer(
    "scan-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="subdomain-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Subdomain Worker Started")

ORGANIZATION_ID = "10024715-cd08-49a4-b316-4f394c14d267"
print("SUBDOMAIN WORKER RUNNING")
print("Waiting for Kafka messages...")
for message in consumer:

    print("KAFKA MESSAGE RECEIVED:", message.value)

    try:

        event = message.value

        if event["event_type"] != "scan_started":
            continue

        scan_id = event.get("scan_id")
        target = event["domain"]

        logger.info(f"Starting asset discovery → {target}")

        assets = discover_subdomains(target)

        logger.info(f"Discovered {len(assets)} assets")

        if not assets:
            assets = [target]

        db = SessionLocal()

        for asset in assets:

            asset = asset.lower().strip()

            if "*" in asset:
                continue

            if " " in asset or "/" in asset:
                continue

            sub_record = store_subdomain(
                db,
                ORGANIZATION_ID,
                target,
                asset
            )

            if sub_record:

                send_asset_discovered(
                    asset,
                    target,
                    scan_id
                )

        db.close()

    except Exception as e:

        logger.error("Subdomain worker crashed")
        logger.error(e)