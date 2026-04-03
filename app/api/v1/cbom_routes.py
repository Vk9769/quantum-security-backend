from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.postgres import get_db
from app.models.cbom import CBOMInventory
from app.models.certificate import Certificate
from app.models.asset_registry import AssetRegistry

router = APIRouter()


@router.get("/dashboard")
def get_cbom_dashboard(db: Session = Depends(get_db)):

    # -----------------------------
    # SUMMARY
    # -----------------------------
    total_apps = db.query(func.count(AssetRegistry.id)).scalar()

    from sqlalchemy import distinct

    total_certs = db.query(
        func.count(distinct(CBOMInventory.certificate_id))
    ).scalar()

    weak_crypto = db.query(CBOMInventory).filter(
        CBOMInventory.key_exchange.ilike("%RSA%")
    ).count()

    # -----------------------------
    # KEY LENGTH DISTRIBUTION
    # -----------------------------
    key_lengths = (
        db.query(Certificate.key_size, func.count().label("count"))
        .group_by(Certificate.key_size)
        .all()
    )

    # -----------------------------
    # CIPHER USAGE
    # -----------------------------
    cipher_usage = (
        db.query(CBOMInventory.cipher_suite, func.count().label("count"))
        .group_by(CBOMInventory.cipher_suite)
        .all()
    )

    # -----------------------------
    # CERTIFICATE AUTHORITIES
    # -----------------------------
    authorities = (
        db.query(Certificate.issuer, func.count().label("count"))
        .group_by(Certificate.issuer)
        .all()
    )

    # -----------------------------
    # TLS PROTOCOLS
    # -----------------------------
    from sqlalchemy import distinct

    protocols = (
        db.query(
            CBOMInventory.tls_version,
            func.count(distinct(CBOMInventory.certificate_id)).label("count")
        )
        .group_by(CBOMInventory.tls_version)
        .all()
    )

    # -----------------------------
    # TABLE DATA (JOIN)
    # -----------------------------
    rows = (
        db.query(
            AssetRegistry.asset_identifier,
            Certificate.key_size,
            CBOMInventory.cipher_suite,
            Certificate.issuer
        )
        .join(CBOMInventory, CBOMInventory.asset_id == AssetRegistry.id)
        .join(Certificate, Certificate.id == CBOMInventory.certificate_id)
        .all()
    )

    return {
        "summary": {
            "total_apps": total_apps or 0,
            "total_certs": total_certs or 0,
            "weak_crypto": weak_crypto or 0
        },
        "key_lengths": [
            {"key_size": k[0], "count": k[1]} for k in key_lengths
        ],
        "cipher_usage": [
            {"cipher_suite": c[0], "count": c[1]} for c in cipher_usage
        ],
        "authorities": [
            {"issuer": a[0], "count": a[1]} for a in authorities
        ],
        "protocols": [
            {"tls_version": p[0], "count": p[1]} for p in protocols
        ],
        "rows": [
            {
                "asset_identifier": r[0],
                "key_size": r[1],
                "cipher_suite": r[2],
                "issuer": r[3]
            } for r in rows
        ]
    }