from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.services.risk_service import (
    get_global_risk_score,
    get_risk_tiers,
    get_domain_risk_score,
    get_domain_risk_tiers,
    get_scan_risk_tiers  
)
from app.schemas.risk_schema import (
    RiskScoreResponse,
    RiskTierItem,
    DomainRiskResponse,
    DomainRiskTierItem,
)

router = APIRouter()


@router.get("/risk", response_model=RiskScoreResponse)
def get_risk_score(db: Session = Depends(get_db)):
    return get_global_risk_score(db)


@router.get("/risk/tiers", response_model=list[RiskTierItem])
def fetch_risk_tiers(db: Session = Depends(get_db)):
    return get_risk_tiers(db)


@router.get("/risk/domain/{domain}", response_model=DomainRiskResponse)
def fetch_domain_risk(domain: str, db: Session = Depends(get_db)):
    return get_domain_risk_score(db, domain)


@router.get("/risk/domain/{domain}/tiers", response_model=list[DomainRiskTierItem])
def fetch_domain_risk_tier(domain: str, db: Session = Depends(get_db)):
    return get_domain_risk_tiers(db, domain)

@router.get("/risk/scan/{scan_id}/tiers", response_model=list[RiskTierItem])
def fetch_scan_risk_tiers(scan_id: str, db: Session = Depends(get_db)):
    return get_scan_risk_tiers(db, scan_id)


