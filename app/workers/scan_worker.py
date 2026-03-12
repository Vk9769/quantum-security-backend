import json
import logging
from kafka import KafkaConsumer
from app.services.graph_service import GraphService

graph = GraphService()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ScanWorker")

consumer = KafkaConsumer(
    "scan-events",
    "asset-events",
    "port-scan-events",
    "tls-events",
    "certificate-events",
    "cbom-events",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    group_id=None,
    enable_auto_commit=False,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Scan Worker Started")

def extract_domain(hostname):
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname

for message in consumer:

    event = message.value
    print("EVENT RECEIVED:", event)
    event_type = event.get("event_type")

    if event_type == "scan_started":
        domain = event["domain"]
        print(f"🔍 Scan started for {domain}")
        graph.create_domain(domain)


    elif event_type == "asset_discovered":

        asset = event["asset"]

        # try to get domain from event
        domain = event.get("domain")

        # if not present, extract from hostname
        if not domain:
            domain = extract_domain(asset)

        print(f"🌐 Asset discovered: {asset} (domain: {domain})")

        graph.create_domain(domain)
        graph.create_asset(domain, asset)
            
    elif event_type == "port_open":

        asset = event["asset"]
        port = event["port"]

        print(f"🔓 Open port discovered → {asset}:{port}")

        graph.add_port(asset, port)
        
    elif event_type == "tls_scan_result":

        asset = event["asset"]

        print(
            f"🔐 TLS → {asset} {event['tls_version']} {event['cipher_suite']}"
        )
        graph.add_tls(
            asset,
            event["tls_version"],
            event["cipher_suite"]
        )
    
    elif event_type == "certificate_discovered":

        print(
            f"📜 Certificate → {event['asset']} "
            f"Issuer={event['issuer']} "
            f"Expires={event['expiry']}"
        )
        graph.add_certificate(
            event["asset"],
            event["issuer"],
            event["subject"],
            event["expiry"],
            event["signature_algorithm"],
            event["key_size"]
        )
        
    elif event_type == "cbom_generated":

        print(
            f"🧾 CBOM → {event['asset']} "
            f"Algo={event['signature_algorithm']} "
            f"KeySize={event['key_size']} "
            f"Expiry={event['expiry']}"
        )
        graph.add_cbom(
            event["asset"],
            event["signature_algorithm"],
            event["key_size"],
            event["expiry"]
        )