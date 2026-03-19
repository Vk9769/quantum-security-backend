import json
import logging
import asyncio

from kafka import KafkaConsumer

from app.services.graph_service import GraphService
from app.utils.websocket_manager import manager


# -------------------- INIT --------------------
graph = GraphService()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s - %(message)s",
    force=True
)

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("KafkaConsumer")


consumer = KafkaConsumer(
    "scan-events",
    "asset-events",
    "tls-events",
    "vulnerability-events",
    "alert-events",
    "port-scan-events",
    "drift-alerts",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    enable_auto_commit=True,
    group_id="kafka-consumer",
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Kafka consumer started")
print("Waiting for Kafka messages...")


# -------------------- ASYNC LOOP --------------------

async def send_topology_update(node, parent):
    try:
        await manager.broadcast({
            "type": "topology_update",
            "node": node,
            "parent": parent
        })
    except Exception as e:
        logger.error(f"WS topology error: {e}")


# -------------------- MAIN LOOP --------------------

for message in consumer:

    try:
        event = message.value

        logger.info(f"📩 Event received → {event}")

        # DEBUG PRINTS
        print("KAFKA MESSAGE RECEIVED:", event)
        print(
            f"TOPIC={message.topic} "
            f"PARTITION={message.partition} "
            f"OFFSET={message.offset}"
        )

        # ==============================
        # SCAN STARTED
        # ==============================
        if event_type == "scan_started":

            domain = event.get("domain")

            log_msg = f"🔍 Scan started for {domain}"
            print(log_msg)


        # ==============================
        # ASSET DISCOVERED
        # ==============================
        elif event_type == "asset_discovered":

            asset = event.get("asset")
            parent = event.get("parent")

            log_msg = f"🌐 Asset discovered → {asset}"
            print(log_msg)

            run_async(send_topology_update(asset, parent))


        # ==============================
        # PORT SCAN
        # ==============================
        elif event_type == "port_open":

            asset = event.get("asset")
            port = event.get("port")

            log_msg = f"🔓 Port open → {asset}:{port}"
            print(log_msg)

            graph.add_port(asset, port)

            run_async(send_topology_update(f"{asset}:{port}", asset))


        # ==============================
        # TLS SCAN
        # ==============================
        elif event_type == "tls_scan_result":

            asset = event.get("asset")
            tls = event.get("tls_version")

            log_msg = f"🔐 TLS detected → {asset} ({tls})"
            print(log_msg)



        # ==============================
        # VULNERABILITY
        # ==============================
        elif event_type == "vulnerability_detected":

            asset = event.get("asset")
            vuln = event.get("vulnerability")

            log_msg = f"⚠️ Vulnerability → {asset} ({vuln})"
            print(log_msg)



        # ==============================
        # ALERT
        # ==============================
        elif event_type == "alert":

            alert_msg = event.get("message")

            log_msg = f"🚨 ALERT → {alert_msg}"
            print(log_msg)


        # ==============================
        # SCAN COMPLETED (IMPORTANT 🔥)
        # ==============================
        elif event_type == "scan_completed":

            log_msg = "✅ Scan completed"
            print(log_msg)

    except Exception as e:

        logger.error("❌ Kafka consumer error")
        logger.error(e)
