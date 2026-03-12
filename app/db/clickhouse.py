import os
import clickhouse_connect
from dotenv import load_dotenv

load_dotenv()

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", 8123))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "security_scanner")

try:

    client = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        database=CLICKHOUSE_DB
    )

    print("✅ ClickHouse connected")

except Exception as e:

    print("❌ ClickHouse connection error:", e)
    client = None