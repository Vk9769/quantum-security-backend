import json
import logging
import time
from kafka import KafkaConsumer

from app.db.postgres import SessionLocal
from app.services.asset_service import store_subdomain
from app.scanners.subdomain_scanner import discover_subdomains
from app.workers.kafka_producer import send_asset_discovered
from app.services.graph_service import GraphService
from app.models.organization import Organization
from app.models.topology import TopologyNode, TopologyEdge
from app.utils.log_streamer import setup_logger
from app.workers.kafka_producer import send_event

# ✅ CONTROL
from app.utils.scan_control import check_scan_control

# ✅ CHECKPOINT
from app.utils.checkpoint import save_checkpoint, get_checkpoint


def send_log(message: str, scan_id: str = None):
    send_event("scan-logs", {
        "type": "log",
        "message": message,
        "scan_id": scan_id
    })


def normalize_host(value: str) -> str:
    if not value:
        return ""

    return (
        str(value).strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


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
    target = None
    scan_id = None

    try:
        event = message.value
        logger.info(f"📩 EVENT RECEIVED: {event}")

        scan_id = event.get("scan_id")

        # =====================================================
        # 🔥 GLOBAL CONTROL (FAST EXIT)
        # =====================================================
        status = check_scan_control(scan_id)

        if status == "paused":
            time.sleep(2)
            continue

        if status == "stopped":
            logger.info(f"⛔ Hard stop → {scan_id}")
            continue
        # =====================================================

        if event.get("event_type") != "scan_started":
            continue

        if not scan_id:
            logger.warning("No scan_id in incoming event")

        organization_id = event.get("organization_id") or "10024715-cd08-49a4-b316-4f394c14d267"
        target = normalize_host(event.get("domain"))

        if not target:
            logger.warning("No valid target domain in scan_started event")
            continue

        logger.info(f"🔥 Starting asset discovery → {target}")

        # ---------------- GRAPH ROOT ----------------
        try:
            graph.create_domain(target)
        except Exception as e:
            logger.warning(f"Graph domain creation failed: {e}")

        # =====================================================
        # 🔥 SAFE DISCOVERY (INTERRUPTIBLE)
        # =====================================================
        assets = []

        try:
            discovered = discover_subdomains(target)

            for item in discovered:

                # 🔥 CHECK STOP DURING DISCOVERY
                status = check_scan_control(scan_id)

                if status == "stopped":
                    logger.info(f"⛔ Stopped during discovery → {scan_id}")
                    break

                if status == "paused":
                    time.sleep(2)
                    continue

                assets.append(item)

        except Exception as e:
            logger.error(f"Scanner failed: {e}")
            assets = []

        logger.info(f"✅ Discovered {len(assets)} assets")
        send_log(f"📡 Discovered {len(assets)} assets", scan_id)

        if not assets:
            assets = [{
                "subdomain": target,
                "ip_address": None
            }]

        # 🔥 CHECKPOINT LOAD
        checkpoint = get_checkpoint(scan_id)
        resume_from = checkpoint.get("last_asset") if checkpoint else None
        skip = True if resume_from else False

        # ---------------- PROCESS EACH ASSET ----------------
        for item in assets:

            # =====================================================
            # 🔥 CONTROL LOOP
            # =====================================================
            while True:
                status = check_scan_control(scan_id)

                if status == "stopped":
                    break

                if status == "paused":
                    time.sleep(2)
                    continue

                break

            if status == "stopped":
                logger.info(f"⛔ Scan stopped mid-process → {scan_id}")
                break
            # =====================================================

            if not isinstance(item, dict):
                logger.warning(f"Invalid asset format → {item}")
                continue

            asset = item.get("subdomain", "").lower().strip()
            ip_address = item.get("ip_address")

            if not asset:
                continue

            # 🔥 RESUME LOGIC
            if skip:
                if asset == resume_from:
                    skip = False
                else:
                    continue

            if "*" in asset or " " in asset or "/" in asset:
                continue

            try:
                # 🔥 SAVE CHECKPOINT
                save_checkpoint(
                    scan_id,
                    stage="subdomain_scan",
                    last_asset=asset
                )

                sub_record = store_subdomain(
                    db,
                    organization_id,
                    target,
                    asset,
                    ip_address
                )

                if not sub_record:
                    logger.warning(f"Skipping asset because DB store failed → {asset}")
                    continue

                try:
                    graph.create_asset(target, asset)
                except Exception as e:
                    logger.warning(f"Graph asset creation failed for {asset}: {e}")

                create_topology(db, target, asset)

                send_asset_discovered(
                    asset,
                    target,
                    scan_id,
                    organization_id
                )

                try:
                    if ip_address:
                        graph.add_ip(asset, ip_address)
                except Exception as e:
                    logger.warning(f"IP graph insert failed for {asset}: {e}")

                if ip_address:
                    send_log(f"🌐 Found subdomain → {asset} [{ip_address}]", scan_id)
                else:
                    send_log(f"🌐 Found subdomain → {asset}", scan_id)

            except Exception as e:
                logger.error(f"Error processing asset {asset}: {e}")

        db.commit()

        # =====================================================
        # 🔥 FINAL STOP CHECK BEFORE NEXT STAGE
        # =====================================================
        if check_scan_control(scan_id) == "stopped":
            logger.info(f"⛔ Scan stopped before port scan trigger → {scan_id}")
            continue
        # =====================================================

        logger.info("✅ Subdomain scan completed")
        send_log(f"✅ Subdomain scan completed → {target}", scan_id)

        # 🔥 TRIGGER NEXT STAGE
        send_event("port-scan-events", {
            "scan_id": scan_id,
            "event_type": "port_scan_requested",
            "domain": target,
            "organization_id": organization_id
        })

        logger.info(f"🚀 Triggered port scan → {target}")
        send_log(f"🚀 Starting port scan → {target}", scan_id)

    except Exception as e:
        db.rollback()
        logger.error("❌ Subdomain worker crashed")
        logger.error(e)
        send_log(f"❌ Subdomain scan failed → {target or 'unknown'}", scan_id)

    finally:
        db.close()