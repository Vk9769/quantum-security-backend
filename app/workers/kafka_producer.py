import json
import os
import logging
from kafka import KafkaProducer
from dotenv import load_dotenv

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")

# ---------------------------------------------------
# Logging setup
# ---------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [KafkaProducer] %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------
# Create Kafka Producer
# ---------------------------------------------------

try:
    producer = KafkaProducer(
        bootstrap_servers=["127.0.0.1:9092"],
        api_version=(2, 6),
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5,
        linger_ms=5,
        acks="all"
    )

    logger.info(f"Connected to Kafka at {KAFKA_BOOTSTRAP_SERVERS}")

except Exception as e:
    logger.error("Failed to connect to Kafka")
    logger.error(e)
    producer = None


# ---------------------------------------------------
# Send Event to Kafka Topic
# ---------------------------------------------------

def send_event(topic: str, data: dict):
    """
    Send an event to a Kafka topic

    Parameters
    ----------
    topic : str
        Kafka topic name
    data : dict
        Event payload
    """

    if producer is None:
        logger.error("Kafka producer not initialized")
        return

    try:
        future = producer.send(topic, data)
        metadata = future.get(timeout=10)

        logger.info(
            f"Event sent → topic={metadata.topic} "
            f"partition={metadata.partition} "
            f"offset={metadata.offset}"
        )

    except Exception as e:
        logger.error("Kafka event send failed")
        logger.error(e)


# ---------------------------------------------------
# Security Scanner Event Functions
# ---------------------------------------------------

def send_scan_started(domain: str):
    event = {
        "event_type": "scan_started",
        "domain": domain
    }

    send_event("scan-events", event)


def send_asset_discovered(asset: str, domain: str):
    event = {
        "event_type": "asset_discovered",
        "asset": asset,
        "domain": domain
    }

    send_event("asset-events", event)


def send_tls_scan_result(asset: str, tls_version: str, cipher: str):

    event = {
        "event_type": "tls_scan_result",
        "asset": asset,
        "tls_version": tls_version,
        "cipher_suite": cipher
    }

    send_event("tls-events", event)


def send_vulnerability_detected(asset: str, cve: str):
    event = {
        "event_type": "vulnerability_detected",
        "asset": asset,
        "cve": cve
    }

    send_event("vulnerability-events", event)


def send_alert(asset: str, severity: str, message: str):
    event = {
        "event_type": "alert",
        "asset": asset,
        "severity": severity,
        "message": message
    }

    send_event("alert-events", event)


# ---------------------------------------------------
# Close Kafka Producer
# ---------------------------------------------------

def close_producer():
    if producer:
        producer.close()
        logger.info("Kafka producer closed")


# ---------------------------------------------------
# Test Runner
# ---------------------------------------------------

if __name__ == "__main__":

    logger.info("Testing Kafka Producer")

    send_scan_started("bank.in")

    send_asset_discovered("api.bank.in", "bank.in")

    send_tls_scan_result(
        "api.bank.in",
        "TLS1.3",
        "TLS_AES_256_GCM_SHA384"
    )

    send_vulnerability_detected("api.bank.in", "CVE-2024-12345")

    send_alert("api.bank.in", "HIGH", "TLS downgrade detected")

    close_producer()