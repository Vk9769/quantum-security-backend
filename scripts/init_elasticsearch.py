import sys
import os

# add project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.elasticsearch import es


if es is None:
    print("❌ Elasticsearch client not initialized")
    exit()


# ----------------------------
# ASSET INDEX
# ----------------------------

asset_index = {
    "mappings": {
        "properties": {
            "domain": {"type": "keyword"},
            "subdomain": {"type": "keyword"},
            "ip": {"type": "ip"},
            "port": {"type": "integer"},
            "tls_version": {"type": "keyword"},
            "cipher": {"type": "keyword"},
            "organization_id": {"type": "keyword"},
            "first_seen": {"type": "date"}
        }
    }
}

if not es.indices.exists(index="assets"):
    es.indices.create(index="assets", body=asset_index)
    print("✅ assets index created")
else:
    print("ℹ️ assets index already exists")


# ----------------------------
# VULNERABILITY INDEX
# ----------------------------

vuln_index = {
    "mappings": {
        "properties": {
            "cve_id": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "description": {"type": "text"},
            "published": {"type": "date"}
        }
    }
}

if not es.indices.exists(index="vulnerabilities"):
    es.indices.create(index="vulnerabilities", body=vuln_index)
    print("✅ vulnerabilities index created")
else:
    print("ℹ️ vulnerabilities index already exists")


# ----------------------------
# SCAN RESULTS INDEX
# ----------------------------

scan_index = {
    "mappings": {
        "properties": {
            "asset_id": {"type": "keyword"},
            "scan_type": {"type": "keyword"},
            "result": {"type": "text"},
            "timestamp": {"type": "date"}
        }
    }
}

if not es.indices.exists(index="scan-results"):
    es.indices.create(index="scan-results", body=scan_index)
    print("✅ scan-results index created")
else:
    print("ℹ️ scan-results index already exists")


print("🎯 Elasticsearch initialization complete")