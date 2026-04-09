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

# ✅ NEW IMPORT (RUNTIME CONTROL)
from app.utils.runtime_control import stop_scan as runtime_stop
from app.utils.runtime_control import pause_scan as runtime_pause
from app.utils.runtime_control import resume_scan as runtime_resume

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
        worker_manager.ensure_workers_running()

        scan_job = ScanJob(
            organization_id="10024715-cd08-49a4-b316-4f394c14d267",
            scan_type="full",
            trigger="manual",
            status="running",
            started_at=datetime.utcnow(),
            domain=domain
        )

        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)

        scan_id = str(scan_job.id)

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

        event = {
            "event_type": "scan_started",
            "domain": domain,
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        send_event("scan-events", event)

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

@router.get("/status/{scan_id}")
def scan_status(scan_id: str):
    db = SessionLocal()

    try:
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
            "domain": scan.domain or "unknown",
            "status": scan.status,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at
        }

    finally:
        db.close()


# ============================================
# WEBSOCKET
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
# GET ALL SCANS
# ============================================

@router.get("")
def get_all_scans():
    db = SessionLocal()

    try:
        scans = db.query(ScanJob).order_by(ScanJob.started_at.desc()).all()

        return [
            {
                "id": str(s.id),
                "domain": s.domain or "unknown",
                "status": s.status
            }
            for s in scans
        ]

    finally:
        db.close()


# ============================================
# PAUSE SCAN
# ============================================

@router.post("/{scan_id}/pause")
def pause_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status in ["stopped", "completed"]:
            return {"message": f"Cannot pause scan in '{scan.status}' state"}

        scan.status = "paused"
        db.commit()

        # ✅ INSTANT PAUSE (IMPORTANT)
        runtime_pause(scan_id)

        logger.info(f"⏸ Scan paused → {scan_id}")

        return {"message": "Scan paused instantly"}

    finally:
        db.close()


# ============================================
# RESUME SCAN
# ============================================

@router.post("/{scan_id}/resume")
def resume_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status == "completed":
            return {"message": "Cannot resume completed scan"}

        if scan.status == "running":
            return {"message": "Scan already running"}

        scan.status = "running"
        db.commit()

        # ✅ CLEAR FLAGS (VERY IMPORTANT)
        runtime_resume(scan_id)

        logger.info(f"▶ Scan resumed → {scan_id}")

        return {"message": "Scan resumed"}

    finally:
        db.close()


# ============================================
# STOP SCAN
# ============================================

@router.post("/{scan_id}/stop")
def stop_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan.status == "stopped":
            return {"message": "Scan already stopped"}

        scan.status = "stopped"
        scan.finished_at = datetime.utcnow()

        db.commit()

        # ✅ INSTANT STOP (CRITICAL FIX)
        runtime_stop(scan_id)

        logger.info(f"⛔ Scan stopped → {scan_id}")

        return {"message": "Scan stopped instantly"}

    finally:
        db.close()


# ============================================
# DELETE SCAN
# ============================================

@router.delete("/{scan_id}")
def delete_scan(scan_id: str):
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        db.delete(scan)
        db.commit()

        logger.info(f"🗑 Scan deleted → {scan_id}")

        return {"message": "Scan deleted"}

    finally:
        db.close()