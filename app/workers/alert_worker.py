import json
import logging
from kafka import KafkaConsumer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AlertWorker")

consumer = KafkaConsumer(
    "alert-events",
    bootstrap_servers="127.0.0.1:9092",
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    group_id=None,
    value_deserializer=lambda m: json.loads(m.decode("utf-8"))
)

logger.info("Alert Worker Started")

for message in consumer:

    event = message.value

    asset = event["asset"]
    severity = event["severity"]
    message_text = event["message"]

    print(f"🚨 ALERT [{severity}] → {asset}")
    print(f"Message: {message_text}")