import logging
from app.workers.kafka_producer import send_scan_started
from app.db.postgres import SessionLocal
from app.models.asset import Domain

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RunScanner")


def start_scan(domain):

    logger.info(f"Starting scan → {domain}")

    send_scan_started(domain)

    logger.info("Scan event sent to Kafka")


def load_domains():

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


if __name__ == "__main__":

    logger.info("Initializing scan pipeline")

    # TEST DOMAIN
    domains = ["Giftretail.pnbuat.bank.in"]

    for domain in domains:

        start_scan(domain)

    logger.info("Scan pipeline started successfully")