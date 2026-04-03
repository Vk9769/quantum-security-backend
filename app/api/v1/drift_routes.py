from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.db.postgres import get_db
from app.models.scan_deltas import ScanDelta
from app.models.asset_registry import AssetRegistry

router = APIRouter()


# ---------------------------------------------------
# GET ALL DRIFTS (WITH OPTIONAL DOMAIN FILTER)
# ---------------------------------------------------
@router.get("/drifts")
def get_drifts(
    domain: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Fetch latest drift events.

    Optional:
    - domain: filter drifts by asset_identifier (supports subdomains)
    - limit: number of records (default 20)
    """

    query = db.query(ScanDelta)

    # 🔥 FIXED: SUPPORT SUBDOMAINS (IMPORTANT)
    if domain:
        query = query.join(AssetRegistry).filter(
            AssetRegistry.asset_identifier.ilike(f"%{domain}%")
        )

    # 🔥 ORDER BY LATEST
    drifts = query.order_by(ScanDelta.id.desc()).limit(limit).all()

    return [
        {
            "id": str(d.id),
            "asset_id": str(d.asset_id) if d.asset_id else None,
            "type": d.change_type,
            "detail": d.change_description,
        }
        for d in drifts
    ]


# ---------------------------------------------------
# GET DRIFTS BY ASSET ID
# ---------------------------------------------------
@router.get("/drifts/{asset_id}")
def get_drifts_by_asset(
    asset_id: str,
    db: Session = Depends(get_db)
):
    """
    Fetch drift events for a specific asset
    """

    drifts = db.query(ScanDelta).filter(
        ScanDelta.asset_id == asset_id
    ).order_by(ScanDelta.id.desc()).all()

    return [
        {
            "id": str(d.id),
            "type": d.change_type,
            "detail": d.change_description,
        }
        for d in drifts
    ]


# ---------------------------------------------------
# DELETE ALL DRIFTS (OPTIONAL - DEBUG USE)
# ---------------------------------------------------
@router.delete("/drifts/clear")
def clear_drifts(db: Session = Depends(get_db)):
    """
    ⚠️ Deletes all drift records (use only for testing)
    """

    deleted = db.query(ScanDelta).delete()
    db.commit()

    return {
        "message": "All drift records deleted",
        "deleted_count": deleted
    }