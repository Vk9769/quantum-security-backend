from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.alert import Alert
from app.models.asset_registry import AssetRegistry

router = APIRouter()


# ---------------------------------------------------
# GET ALERTS (by scan_id or domain)
# ---------------------------------------------------
@router.get("/alerts")
def get_alerts(
    scan_id: str = Query(None),
    domain: str = Query(None),
    db: Session = Depends(get_db)
):
    query = db.query(Alert, AssetRegistry.asset_identifier).join(
        AssetRegistry, Alert.asset_id == AssetRegistry.id
    )

    # ✅ FILTER BY DOMAIN
    if domain:
        query = query.filter(
            AssetRegistry.asset_identifier.ilike(f"%{domain}%")
        )

    results = query.order_by(Alert.created_at.desc()).limit(20).all()

    return [
        {
            "id": str(alert.id),
            "severity": alert.severity,
            "message": alert.description,
            "asset": asset_identifier,
            "created_at": alert.created_at.isoformat() if alert.created_at else None
        }
        for alert, asset_identifier in results
    ]