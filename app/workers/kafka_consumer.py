import json
import logging
from kafka import KafkaConsumer
from app.services.graph_service import GraphService

graph = GraphService()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("KafkaConsumer")

consumer = KafkaConsumer(
    "scan-events",
    "asset-events",
    "tls-events",
    "vulnerability-events",
    "alert-events",
    "port-scan-events",
    "drift-alerts",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    group_id=None,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Kafka consumer started")


for message in consumer:
    
    print(
        f"TOPIC={message.topic} "
        f"PARTITION={message.partition} "
        f"OFFSET={message.offset} "
        f"VALUE={message.value}"
    )

    event = message.value
    
    print("TOPIC:", message.topic)
    print("EVENT:", event)

    logger.info(f"Received event: {event}")

    event_type = event.get("event_type")

    if event_type == "scan_started":
        print("Scan started for", event["domain"])

    elif event_type == "asset_discovered":
        print("Asset discovered:", event["asset"])
        
    elif event_type == "port_open":

        asset = event["asset"]
        port = event["port"]

        print(f"🔓 Port discovered → {asset}:{port}")

        graph.add_port(asset, port)

    elif event_type == "tls_scan_result":
        print("TLS result:", event)

    elif event_type == "vulnerability_detected":
        print("Vulnerability:", event)

    elif event_type == "alert":
        print("Security alert:", event)
        
    