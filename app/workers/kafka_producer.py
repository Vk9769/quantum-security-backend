import json
import os
import logging
import uuid

from kafka import KafkaProducer
from dotenv import load_dotenv


# ---------------------------------------------------
# LOAD ENV
# ---------------------------------------------------

load_dotenv()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092")


# ---------------------------------------------------
# LOGGING
# ---------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [KafkaProducer] %(levelname)s - %(message)s"
)

logger = logging.getLogger("KafkaProducer")


# ---------------------------------------------------
# JSON SERIALIZER
# ---------------------------------------------------

def json_serializer(value):
    try:
        return json.dumps(value).encode("utf-8")
    except Exception as e:
        logger.error("JSON serialization failed")
        logger.error(e)
        return None


# ---------------------------------------------------
# NORMALIZATION
# ---------------------------------------------------

def normalize_asset(value: str) -> str:
    if not value:
        return ""

    return (
        str(value).strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


# ---------------------------------------------------
# KAFKA PRODUCER INIT (RETRY SAFE)
# ---------------------------------------------------

producer = None


def init_producer():
    global producer

    if producer:
        return producer

    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            api_version=(2, 6),
            value_serializer=json_serializer,
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            retries=5,
            linger_ms=10,
            acks="all",
            request_timeout_ms=30000
        )

        logger.info(f"Connected to Kafka at {KAFKA_BOOTSTRAP_SERVERS}")

    except Exception as e:
        logger.error("Kafka connection failed")
        logger.error(e)

    return producer


# initialize on import
init_producer()


# ---------------------------------------------------
# GENERIC EVENT SENDER
# ---------------------------------------------------

def send_event(topic: str, data: dict, key: str = None):
    global producer

    if producer is None:
        logger.warning("Producer not initialized, retrying...")
        producer = init_producer()

        if producer is None:
            logger.error("Kafka producer unavailable")
            return

    try:
        payload = dict(data) if data else {}

        if "scan_id" not in payload or payload.get("scan_id") is None:
            payload["scan_id"] = "unknown"

        # normalize common asset fields
        if payload.get("asset"):
            payload["asset"] = normalize_asset(payload["asset"])

        if payload.get("domain"):
            payload["domain"] = normalize_asset(payload["domain"])

        kafka_key = key
        if kafka_key:
            kafka_key = normalize_asset(kafka_key)

        future = producer.send(
            topic,
            value=payload,
            key=kafka_key
        )

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
# PIPELINE EVENTS
# ---------------------------------------------------

def send_scan_started(domain: str, scan_id: str, organization_id: str = None):
    domain = normalize_asset(domain)

    event = {
        "scan_id": scan_id,
        "event_type": "scan_started",
        "domain": domain,
        "organization_id": organization_id
    }

    send_event("scan-events", event, key=domain)


def send_asset_discovered(asset: str, domain: str, scan_id: str, organization_id: str = None):
    asset = normalize_asset(asset)
    domain = normalize_asset(domain)

    event = {
        "scan_id": scan_id,
        "event_type": "asset_discovered",
        "asset": asset,
        "domain": domain,
        "organization_id": organization_id
    }

    send_event("asset-events", event, key=asset)


def send_port_open(asset: str, port: int, scan_id: str, organization_id: str = None):
    asset = normalize_asset(asset)

    event = {
        "scan_id": scan_id,
        "event_type": "port_open",
        "asset": asset,
        "port": port,
        "organization_id": organization_id
    }

    send_event("port-scan-events", event, key=asset)


def send_tls_scan_result(
    asset: str,
    tls_version: str,
    cipher: str,
    scan_id: str,
    organization_id: str = None,
    key_exchange: str = None,
    certificate_issuer: str = None,
    certificate_subject: str = None,
    signature_algorithm: str = None,
    key_size: int = None,
    expiry: str = None,
    forward_secrecy: bool = None
):
    asset = normalize_asset(asset)

    event = {
        "scan_id": scan_id,
        "event_type": "tls_scan_result",
        "asset": asset,
        "tls_version": tls_version,
        "cipher_suite": cipher,
        "key_exchange": key_exchange,
        "certificate_issuer": certificate_issuer,
        "certificate_subject": certificate_subject,
        "signature_algorithm": signature_algorithm,
        "key_size": key_size,
        "expiry": expiry,
        "forward_secrecy": forward_secrecy,
        "organization_id": organization_id
    }

    send_event("tls-events", event, key=asset)


def send_certificate_discovered(cert_data: dict, scan_id: str, organization_id: str = None):
    payload = dict(cert_data) if cert_data else {}

    if payload.get("asset"):
        payload["asset"] = normalize_asset(payload["asset"])

    payload.update({
        "scan_id": scan_id,
        "event_type": "certificate_discovered",
        "organization_id": organization_id
    })

    send_event("certificate-events", payload, key=payload.get("asset"))


def send_cbom_generated(cbom_data: dict, scan_id: str, organization_id: str = None):
    payload = dict(cbom_data) if cbom_data else {}

    if payload.get("asset"):
        payload["asset"] = normalize_asset(payload["asset"])

    payload.update({
        "scan_id": scan_id,
        "event_type": "cbom_generated",
        "organization_id": organization_id
    })

    send_event("cbom-events", payload, key=payload.get("asset"))


def send_vulnerability_detected(asset: str, cve: str, scan_id: str, organization_id: str = None):
    asset = normalize_asset(asset)

    event = {
        "scan_id": scan_id,
        "event_type": "vulnerability_detected",
        "asset": asset,
        "cve": cve,
        "organization_id": organization_id
    }

    send_event("vulnerability-events", event, key=asset)


def send_alert(asset: str, severity: str, message: str, scan_id: str, organization_id: str = None):
    asset = normalize_asset(asset)

    event = {
        "scan_id": scan_id,
        "event_type": "alert",
        "asset": asset,
        "severity": severity,
        "message": message,
        "organization_id": organization_id
    }

    send_event("alert-events", event, key=asset)


# ---------------------------------------------------
# SHUTDOWN
# ---------------------------------------------------

def close_producer():
    global producer

    if producer:
        try:
            producer.flush()
            producer.close()
            logger.info("Kafka producer closed")

        except Exception as e:
            logger.error("Error closing producer")
            logger.error(e)


# ---------------------------------------------------
# TEST RUNNER
# ---------------------------------------------------

if __name__ == "__main__":
    logger.info("Testing Kafka Producer")

    scan_id = str(uuid.uuid4())
    organization_id = "10024715-cd08-49a4-b316-4f394c14d267"

    send_scan_started("bank.in", scan_id, organization_id)

    send_asset_discovered(
        "api.bank.in",
        "bank.in",
        scan_id,
        organization_id
    )

    send_tls_scan_result(
        asset="api.bank.in",
        tls_version="TLS1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        scan_id=scan_id,
        organization_id=organization_id,
        key_exchange="X25519",
        certificate_issuer="Test CA",
        certificate_subject="api.bank.in",
        signature_algorithm="RSA-SHA256",
        key_size=2048,
        expiry="2027-12-31T00:00:00"
    )

    send_vulnerability_detected(
        "api.bank.in",
        "CVE-2024-12345",
        scan_id,
        organization_id
    )

    send_alert(
        "api.bank.in",
        "HIGH",
        "TLS downgrade detected",
        scan_id,
        organization_id
    )

    close_producer()