import os
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST", "http://localhost:9200")

try:

    es = Elasticsearch(
        hosts=[ELASTIC_HOST]
    )

    if es.ping():
        print("✅ Elasticsearch connected")
    else:
        print("❌ Elasticsearch ping failed")

except Exception as e:

    print("❌ Elasticsearch connection error:", e)
    es = None