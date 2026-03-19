import json
import logging
import asyncio

from kafka import KafkaConsumer
from app.utils.websocket_manager import manager
from app.utils.log_streamer import get_main_loop

logger = logging.getLogger("LogConsumer")


def start_log_consumer():

    consumer = KafkaConsumer(
        "scan-logs",  # 🔥 IMPORTANT TOPIC
        bootstrap_servers="localhost:9092",
        auto_offset_reset="latest",
        enable_auto_commit=True,
        group_id="log-consumer-group",
        value_deserializer=lambda m: json.loads(m.decode("utf-8"))
    )

    logger.info("🔥 Log Consumer Started (scan-logs)")

    for message in consumer:

        try:
            data = message.value

            print("📥 LOG FROM KAFKA:", data)

            if data.get("type") != "log":
                continue

            scan_id = data.get("scan_id")

            if not scan_id:
                logger.warning(f"⚠ Missing scan_id in log: {data}")

            loop = get_main_loop()

            if loop:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast({
                        "type": "log",
                        "message": data.get("message"),
                        "scan_id": scan_id  # ✅ FIXED
                    }),
                    loop
                )
            else:
                logger.warning("Main loop not set")

        except Exception as e:
            logger.error(f"Log consumer error: {e}")