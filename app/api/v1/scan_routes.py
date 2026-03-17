from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from app.workers.kafka_producer import send_event

router = APIRouter()


# ============================================
# Request Model (for Swagger + validation)
# ============================================

class ScanRequest(BaseModel):
    domain: str


# ============================================
# START SECURITY SCAN
# ============================================

@router.post("/scan/start")
def start_scan(payload: ScanRequest):

    domain = payload.domain.strip()

    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    event = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat()
    }

    # Send event to Kafka so workers start scanning
    send_event("scan_start", event)

    return {
        "status": "started",
        "domain": domain,
        "message": "Scan initiated successfully"
    }


# ============================================
# SCAN STATUS (for loader / progress UI)
# ============================================

@router.get("/scan/status/{domain}")
def scan_status(domain: str):

    # Placeholder for now
    # Later this will check DB or Redis

    return {
        "domain": domain,
        "status": "running"
    }