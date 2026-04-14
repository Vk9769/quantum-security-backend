from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.scan_jobs import ScanJob  # make sure this model exists

router = APIRouter()


# ---------------------------------------------------
# Get latest scan for a domain
# ---------------------------------------------------
@router.get("/scan-history/latest")
def get_latest_scan(
    domain: str = Query(...),
    db: Session = Depends(get_db)
):
    scan = (
        db.query(ScanJob)
        .filter(ScanJob.domain == domain)
        .order_by(ScanJob.started_at.desc())
        .first()
    )

    if not scan:
        return {"scan_id": None}

    return {
        "scan_id": str(scan.id),
        "domain": scan.domain,
        "status": scan.status,
        "started_at": scan.started_at,
    }


# ---------------------------------------------------
# Get all scans for a domain (optional - future use)
# ---------------------------------------------------
@router.get("/scan-history/list")
def get_scan_history(
    domain: str = Query(...),
    db: Session = Depends(get_db)
):
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.domain == domain)
        .order_by(ScanJob.started_at.desc())
        .all()
    )

    return [
        {
            "scan_id": str(s.id),
            "domain": s.domain,
            "status": s.status,
            "started_at": s.started_at,
        }
        for s in scans
    ]