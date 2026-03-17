from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate

router = APIRouter()


# =====================================================
# TLS SUMMARY FOR DASHBOARD
# =====================================================

@router.get("/tls/summary")
def tls_summary(db: Session = Depends(get_db)):

    endpoints = db.query(TLSScanResult).count()

    weak_ciphers = 0
    expired_certs = db.query(Certificate).filter(
        getattr(Certificate, "is_expired", False) == True
    ).count()

    hsts_enabled = 0

    return {
        "endpoints": endpoints,
        "weak_ciphers": weak_ciphers,
        "expired_certs": expired_certs,
        "hsts_enabled": hsts_enabled
    }


# =====================================================
# LIST TLS RESULTS
# =====================================================

@router.get("/tls")
def list_tls_results(db: Session = Depends(get_db)):

    results = db.query(TLSScanResult).all()

    data = []

    for r in results:
        data.append({
            "asset_id": getattr(r, "asset_id", None),
            "hostname": getattr(r, "hostname", None),
            "port": getattr(r, "port", None),
            "tls_version": getattr(r, "tls_version", None),
        })

    return data