from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.schemas.asset_schema import (
    AssetResponse,
    AssetSummaryCard,
    AssetCountsResponse,
)
from app.services.asset_service import (
    get_assets_visibility,
    get_assets_counts,
    get_assets_summary_data,
)

router = APIRouter()


# ---------------------------------------------------
# Get Assets Visibility
# ---------------------------------------------------
@router.get("/assets", response_model=list[AssetResponse])
def get_assets(
    asset_type: str = Query("all", description="all | domain | subdomain | ip | ssl | software"),
    scan_id: str = Query(...),   # ✅ ADD THIS (REQUIRED)
    db: Session = Depends(get_db)
):
    return get_assets_visibility(
        db=db,
        asset_type=asset_type,
        scan_id=scan_id   # ✅ PASS SCAN ID
    )


# ---------------------------------------------------
# Get Asset Counts for Tabs
# ---------------------------------------------------
@router.get("/assets/counts", response_model=AssetCountsResponse)
def get_asset_counts(
    scan_id: str = Query(...),   # ✅ ADD THIS
    db: Session = Depends(get_db)
):
    return get_assets_counts(
        db=db,
        scan_id=scan_id   # ✅ PASS SCAN ID
    )


# ---------------------------------------------------
# Assets Summary (for dashboard cards)
# ---------------------------------------------------
@router.get("/assets/summary", response_model=list[AssetSummaryCard])
def get_assets_summary(
    scan_id: str = Query(...),   # ✅ REQUIRED PARAM
    db: Session = Depends(get_db)
):
    return get_assets_summary_data(db=db, scan_id=scan_id)