from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.postgres import get_db
from app.models.tls import TLSScanResult

router = APIRouter()


# =====================================================
# TLS SUMMARY FOR DASHBOARD
# =====================================================

@router.get("/tls/summary")
def tls_summary(db: Session = Depends(get_db)):
    endpoints = db.query(TLSScanResult).count()

    weak_cipher_query = text("""
        SELECT COUNT(*)
        FROM tls_scan_results
        WHERE cipher_suite IS NOT NULL
          AND (
                cipher_suite ILIKE '%RC4%'
             OR cipher_suite ILIKE '%3DES%'
             OR cipher_suite ILIKE '%DES%'
             OR cipher_suite ILIKE '%MD5%'
             OR cipher_suite ILIKE '%NULL%'
             OR cipher_suite ILIKE '%EXPORT%'
             OR cipher_suite ILIKE '%anon%'
          )
    """)

    expired_certs_query = text("""
        SELECT COUNT(*)
        FROM certificates
        WHERE expiry_date IS NOT NULL
          AND expiry_date < CURRENT_DATE
    """)

    # Current schema has no hsts flag/table column, so keep safe fallback
    hsts_enabled = 0

    weak_ciphers = db.execute(weak_cipher_query).scalar() or 0
    expired_certs = db.execute(expired_certs_query).scalar() or 0

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
            "cipher_suite": getattr(r, "cipher_suite", None),
            "key_exchange": getattr(r, "key_exchange", None),
            "forward_secrecy": getattr(r, "forward_secrecy", None),
            "scan_time": getattr(r, "scan_time", None),
        })

    return data