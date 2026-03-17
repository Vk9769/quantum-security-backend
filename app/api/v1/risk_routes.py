from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate

router = APIRouter()


# =====================================================
# GLOBAL RISK SCORE
# =====================================================

@router.get("/risk")
def get_risk_score(db: Session = Depends(get_db)):
    """
    Returns overall enterprise security score (0-100)
    """

    total_assets = db.query(AssetRegistry).count()

    if total_assets == 0:
        return {"score": 100}

    weak_tls = db.query(TLSScanResult).filter(
        getattr(TLSScanResult, "tls_version", "") != "TLS 1.3"
    ).count()

    expired_certs = db.query(Certificate).filter(
        getattr(Certificate, "is_expired", False) == True
    ).count()

    # simple scoring model
    risk_penalty = (weak_tls * 2) + (expired_certs * 3)

    score = max(100 - risk_penalty, 0)

    return {
        "score": score
    }


# =====================================================
# RISK TIERS FOR DASHBOARD
# =====================================================

@router.get("/risk/tiers")
def get_risk_tiers(db: Session = Depends(get_db)):
    """
    Returns tier distribution used in RiskTierPanel
    """

    pqc_enabled = db.query(AssetRegistry).filter(
        getattr(AssetRegistry, "pqc_status", "") == "pqc"
    ).count()

    tls13 = db.query(TLSScanResult).filter(
        getattr(TLSScanResult, "tls_version", "") == "TLS 1.3"
    ).count()

    weak_tls = db.query(TLSScanResult).filter(
        getattr(TLSScanResult, "tls_version", "") != "TLS 1.3"
    ).count()

    critical = db.query(Certificate).filter(
        getattr(Certificate, "is_expired", False) == True
    ).count()

    tiers = [
        {
            "label": "Elite (PQC Enabled)",
            "count": pqc_enabled,
            "color": "bg-success",
            "textColor": "text-success"
        },
        {
            "label": "Standard (TLS 1.3)",
            "count": tls13,
            "color": "bg-primary",
            "textColor": "text-primary"
        },
        {
            "label": "Legacy (Weak TLS)",
            "count": weak_tls,
            "color": "bg-warning",
            "textColor": "text-warning"
        },
        {
            "label": "Critical",
            "count": critical,
            "color": "bg-destructive",
            "textColor": "text-destructive"
        }
    ]

    return tiers