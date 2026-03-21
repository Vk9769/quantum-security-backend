from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.schemas.pqc_schema import PQCDashboardResponse
from app.services.pqc_service import build_pqc_dashboard

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