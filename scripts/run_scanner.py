import logging
import uuid
from datetime import datetime

from app.workers.kafka_producer import send_scan_started
from app.db.postgres import SessionLocal
from app.models.asset import Domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RunScanner")


def start_scan(domain: str, scan_id: str = None):
    """
    Starts scan for a given domain
    """

    # Generate scan_id if not provided
    if not scan_id:
        scan_id = str(uuid.uuid4())

    logger.info(f"Starting scan → {domain}")
    logger.info(f"Scan ID → {scan_id}")

    try:
        # Send event to Kafka with scan_id
        send_scan_started(domain, scan_id)

        logger.info("Scan event sent to Kafka successfully")

    except Exception as e:
        logger.error("Failed to send scan event to Kafka")
        logger.error(e)

    return scan_id


def load_domains():
    """
    Load domains from DB (optional use)
    """

    db = SessionLocal()

    try:
        domains = db.query(Domain.domain_name).all()
        return [d[0] for d in domains]

    except Exception as e:
        logger.error("Failed to load domains")
        logger.error(e)
        return []

    finally:
        db.close()


# CLI runner
def run():
    """
    Entry point for manual scan execution
    """

    logger.info("Initializing scan pipeline")

    # OPTION 1: Static domains (current behavior)
    domains = ["digiel.pnbuat.bank.in"]

    # OPTION 2: Uncomment to load from DB
    # domains = load_domains()

    for domain in domains:
        scan_id = start_scan(domain)

        logger.info(f"Scan triggered → {domain} | Scan ID → {scan_id}")

    logger.info("Scan pipeline started successfully")


if __name__ == "__main__":
    run()