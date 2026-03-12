import json
import logging
from kafka import KafkaProducer
from app.db.postgres import SessionLocal
from app.services.asset_service import store_subdomain

from app.scanners.subdomain_scanner import discover_subdomains

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SubdomainWorker")


producer = KafkaProducer(
    bootstrap_servers="127.0.0.1:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)


def send_asset(asset, domain):

    event = {
        "event_type": "asset_discovered",
        "asset": asset,
        "domain": domain
    }

    producer.send("asset-events", event)
    producer.flush()

    logger.info(f"Asset sent → {asset}")


if __name__ == "__main__":

    target = "tesla.com"

    logger.info(f"Starting subdomain scan → {target}")

    subdomains = discover_subdomains(target)

    logger.info(f"Discovered {len(subdomains)} subdomains")
    
    ORGANIZATION_ID = "10024715-cd08-49a4-b316-4f394c14d267"

    db = SessionLocal()

    for sub in subdomains:

        sub = sub.lower().strip()

        if "*" in sub:
            continue

        if " " in sub or "/" in sub:
            continue

        print("FOUND:", sub)

        store_subdomain(
            db,
            ORGANIZATION_ID,
            target,
            sub
        )

        send_asset(sub, target)

    db.close()
    
    producer.close()