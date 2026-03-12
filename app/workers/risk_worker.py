import json
import logging
from kafka import KafkaConsumer

from app.services.graph_service import GraphService
from app.ai.quantum_risk_analyzer import analyze_quantum_risk

graph = GraphService()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RiskWorker")

consumer = KafkaConsumer(
    "vulnerability-events",
    "cbom-events",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    group_id=None,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Risk Worker Started")


def calculate_risk_score(base=0, quantum=False, vulnerability=False):
    score = base

    if vulnerability:
        score += 70

    if quantum:
        score += 40

    if score > 100:
        score = 100

    return score


for message in consumer:

    event = message.value
    event_type = event.get("event_type")

    # -----------------------------------
    # Vulnerability Events
    # -----------------------------------
    if event_type == "vulnerability_detected":

        asset = event["asset"]
        cve = event["cve"]

        graph.add_vulnerability(asset, cve)

        logger.info(f"⚠️ Vulnerability detected → {asset} {cve}")

        risk_score = calculate_risk_score(vulnerability=True)

        logger.info(f"📊 Risk Score → {asset} = {risk_score}")

    # -----------------------------------
    # Quantum Crypto Risk
    # -----------------------------------
    elif event_type == "cbom_generated":

        asset = event["asset"]

        quantum_risk = analyze_quantum_risk(event)

        logger.info(
            f"⚛ Quantum Risk → {asset} "
            f"Algo={event.get('signature_algorithm')} "
            f"Risk={quantum_risk}"
        )

        if quantum_risk == "NOT_QUANTUM_SAFE":
            risk_score = calculate_risk_score(quantum=True)
        else:
            risk_score = calculate_risk_score()

        logger.info(f"📊 Risk Score → {asset} = {risk_score}")

        # ------------------------------
        # Store risk in Neo4j
        # ------------------------------

        graph.add_risk(asset, risk_score, quantum_risk)