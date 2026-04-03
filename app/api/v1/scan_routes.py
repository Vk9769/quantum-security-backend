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
            organization_id="10024715-cd08-49a4-b316-4f394c14d267",
            scan_type="full",
            trigger="manual",
            status="running",
            started_at=datetime.utcnow(),
            domain=domain  # ✅ ADD THIS
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
# SCAN STATUS (FIXED - USE scan_id)
# ============================================

@router.get("/status/{scan_id}")
def scan_status(scan_id: str):
    db = SessionLocal()

    try:
        # 🔥 GET SPECIFIC SCAN BY ID (NOT latest)
        scan = db.query(ScanJob).filter(
            ScanJob.id == scan_id
        ).first()

        if not scan:
            return {
                "scan_id": scan_id,
                "status": "not_found"
            }

        return {
            "scan_id": str(scan.id),
            "domain": scan.domain if hasattr(scan, "domain") else "unknown",
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at
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


# ============================================
# 🔥 NEW APIs FOR FRONTEND CONTROL
# ============================================

# GET ALL SCANS
@router.get("")
def get_all_scans():
    db = SessionLocal()

    try:
        scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).all()

        return [
            {
                "id": str(s.id),
                "domain": s.domain or "unknown",  # ✅ FIXED
                "status": s.status
            }
            for s in scans
        ]

    finally:    
        db.close()


# PAUSE SCAN
@router.post("/{scan_id}/pause")
def pause_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan.status = "paused"
        db.commit()

        return {"message": "Scan paused"}

    finally:
        db.close()


# RESUME SCAN
@router.post("/{scan_id}/resume")
def resume_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan.status = "running"
        db.commit()

        return {"message": "Scan resumed"}

    finally:
        db.close()


# STOP SCAN
@router.post("/{scan_id}/stop")
def stop_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan.status = "stopped"
        scan.finished_at = datetime.utcnow()

        db.commit()

        return {"message": "Scan stopped"}

    finally:
        db.close()


# DELETE SCAN
@router.delete("/{scan_id}")
def delete_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        db.delete(scan)
        db.commit()

        return {"message": "Scan deleted"}

    finally:
        db.close()