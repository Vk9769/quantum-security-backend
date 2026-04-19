from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.schemas.pqc_schema import PQCDashboardResponse, PQCAppDetails
from app.services.pqc_service import build_pqc_dashboard, get_pqc_asset_details, get_pqc_readiness

router = APIRouter()


@router.get("/pqc", response_model=PQCDashboardResponse)
def get_pqc_dashboard(
    domain: Optional[str] = Query(None, description="Filter by searched domain"),
    db: Session = Depends(get_db)
):
    """
    Returns PQC dashboard data for all assets
    or only for a searched domain.
    """
    return build_pqc_dashboard(db, domain)


@router.get("/pqc/asset-details/{asset_id}", response_model=PQCAppDetails)
def get_asset_details(
    asset_id: UUID,
    db: Session = Depends(get_db)
):
    details = get_pqc_asset_details(db, asset_id)

    if not details:
        raise HTTPException(status_code=404, detail="Asset details not found")

    return details

@router.get("/pqc/readiness")
def pqc_readiness(
    domain: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    return get_pqc_readiness(db, domain, scan_id)