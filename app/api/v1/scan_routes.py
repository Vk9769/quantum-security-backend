from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from datetime import datetime
import asyncio
import logging

from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.models.scan_jobs import ScanJob
from app.workers.kafka_producer import send_event
from app.utils.websocket_manager import manager
from app.workers.worker_manager import worker_manager

router = APIRouter()
logger = logging.getLogger("ScanRoute")


# ============================================
# REQUEST MODEL
# ============================================

class ScanRequest(BaseModel):
    domain: str


# ============================================
# START SECURITY SCAN
# ============================================

@router.post("/start")
def start_scan(payload: ScanRequest):
    domain = payload.domain.strip().lower()

    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    db = SessionLocal()

    try:
        # ============================================
        # 0. ENSURE WORKERS ARE RUNNING
        # ============================================
        worker_manager.ensure_workers_running()

        # ============================================
        # 1. CREATE SCAN JOB
        # ============================================
        scan_job = ScanJob(
            organization_id="10024715-cd08-49a4-b316-4f394c14d267",  # TODO: dynamic later
            scan_type="full",
            trigger="manual",
            status="running",
            started_at=datetime.utcnow()
        )

        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)

        scan_id = str(scan_job.id)

        # ============================================
        # 2. CHECK IF DOMAIN ALREADY EXISTS
        # ============================================
        existing = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == domain
        ).first()

        if not existing:
            asset = AssetRegistry(
                organization_id="10024715-cd08-49a4-b316-4f394c14d267",
                asset_identifier=domain,
                asset_type="domain",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                status="discovered",
                criticality="medium"
            )

            db.add(asset)
            db.commit()

        # ============================================
        # 3. SEND EVENT TO KAFKA
        # ============================================
        event = {
            "event_type": "scan_started",
            "domain": domain,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        send_event("scan-events", event)

        # ============================================
        # 4. SEND REAL-TIME WS LOG
        # ============================================
        logger.info(f"🔍 Scan started for {domain}")

        return {
            "status": "started",
            "domain": domain,
            "scan_id": scan_id,
            "message": "Scan initiated successfully"
        }

    except Exception as e:
        db.rollback()
        logger.exception("SCAN ERROR")
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        db.close()


# ============================================
# SCAN STATUS
# ============================================

@router.get("/status/{domain}")
def scan_status(domain: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob) \
            .order_by(ScanJob.started_at.desc()) \
            .first()

        if not scan:
            return {
                "domain": domain,
                "status": "not_found"
            }

        return {
            "domain": domain,
            "status": scan.status,
            "scan_id": str(scan.id),
            "started_at": scan.started_at
        }

    finally:
        db.close()


# ============================================
# WEBSOCKET FOR REAL-TIME LOGS
# ============================================

@router.websocket("/ws")
async def scan_websocket(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        while True:
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        manager.disconnect(websocket)