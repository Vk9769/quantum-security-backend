import json
import logging
from kafka import KafkaConsumer

from app.db.postgres import SessionLocal
from app.services.asset_service import store_subdomain
from app.scanners.subdomain_scanner import discover_subdomains
from app.workers.kafka_producer import send_asset_discovered
from app.services.graph_service import GraphService

# ⚠️ FIX: correct import path if needed
from app.models.topology import TopologyNode, TopologyEdge
from app.utils.log_streamer import setup_logger
from app.workers.kafka_producer import send_event

def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


# -------------------- LOGGER --------------------
setup_logger()

logging.getLogger("kafka").setLevel(logging.WARNING)
logger = logging.getLogger("SubdomainWorker")


# -------------------- INIT --------------------
graph = GraphService()

consumer = KafkaConsumer(
    "scan-events",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    group_id="subdomain-worker",
    enable_auto_commit=True,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("🚀 Subdomain Worker Started")
print("SUBDOMAIN WORKER RUNNING")
print("Waiting for Kafka messages...")

# -------------------- HELPERS --------------------

def create_topology(db, domain, subdomain):
    """
    Create nodes + edge in topology tables
    """

    # DOMAIN NODE
    domain_node = db.query(TopologyNode).filter(
        TopologyNode.value == domain
    ).first()

    if not domain_node:
        domain_node = TopologyNode(
            node_type="domain",
            value=domain
        )
        db.add(domain_node)
        db.flush()

    # SUBDOMAIN NODE
    sub_node = db.query(TopologyNode).filter(
        TopologyNode.value == subdomain
    ).first()

    if not sub_node:
        sub_node = TopologyNode(
            node_type="subdomain",
            value=subdomain
        )
        db.add(sub_node)
        db.flush()

    # EDGE (avoid duplicate)
    existing_edge = db.query(TopologyEdge).filter(
        TopologyEdge.source_node == domain_node.id,
        TopologyEdge.target_node == sub_node.id
    ).first()

    if not existing_edge:
        edge = TopologyEdge(
            source_node=domain_node.id,
            target_node=sub_node.id,
            relation_type="has_subdomain"
        )
        db.add(edge)

    return domain_node, sub_node

# -------------------- MAIN LOOP --------------------

for message in consumer:

    db = SessionLocal()

    try:
        event = message.value
        logger.info(f"📩 EVENT RECEIVED: {event}")

        if event.get("event_type") != "scan_started":
            continue

        scan_id = event.get("scan_id")
        
        if not scan_id:
            logger.warning(f"No scan_id for {target}")
    
        target = event.get("domain")

        if not target:
            continue

        logger.info(f"🔥 Starting asset discovery → {target}")
        # ---------------- GRAPH ROOT ----------------
        try:
            graph.create_domain(target)
        except Exception as e:
            logger.warning(f"Graph domain creation failed: {e}")

        # ---------------- DISCOVERY ----------------
        try:
            assets = discover_subdomains(target)
        except Exception as e:
            logger.error(f"Scanner failed: {e}")
            assets = []

        logger.info(f"✅ Discovered {len(assets)} assets")
        send_log(f"📡 Discovered {len(assets)} assets", scan_id)

        if not assets:
            assets = [target]

        # ---------------- PROCESS EACH ASSET ----------------
        for asset in assets:

            asset = asset.lower().strip()

            if "*" in asset or " " in asset or "/" in asset:
                continue

            try:
                # STORE IN DB
                sub_record = store_subdomain(
                    db,
                    event.get("organization_id") or "10024715-cd08-49a4-b316-4f394c14d267",
                    target,
                    asset
                )

                if not sub_record:
                    continue

                # GRAPH
                graph.create_asset(target, asset)

                # TOPOLOGY
                create_topology(db, target, asset)

                # KAFKA EVENT
                send_asset_discovered(
                    asset,
                    target,
                    scan_id
                )

                # LIVE UI
                send_log(f"🌐 Found subdomain → {asset}", scan_id)
                
            except Exception as e:
                logger.error(f"Error processing asset {asset}: {e}")

        db.commit()

        logger.info("✅ Subdomain scan completed")
        send_log(f"✅ Subdomain scan completed → {target}", scan_id)

    except Exception as e:

        db.rollback()

        logger.error("❌ Subdomain worker crashed")
        logger.error(e)

        send_log(f"❌ Subdomain scan failed → {target}", scan_id)

    finally:
        db.close()