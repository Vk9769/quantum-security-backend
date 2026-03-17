from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate

router = APIRouter()


# =====================================================
# PQC READINESS SUMMARY
# =====================================================

@router.get("/pqc")
def get_pqc_readiness(db: Session = Depends(get_db)):
    """
    Returns Post-Quantum Cryptography readiness statistics
    used by the PQCReadinessPanel dashboard.
    """

    assets = db.query(AssetRegistry).all()

    pqc_ready = 0
    upgrade_required = 0
    not_pqc = 0

    for a in assets:

        status = getattr(a, "pqc_status", None)

        if status == "pqc":
            pqc_ready += 1

        elif status == "upgrade":
            upgrade_required += 1

        else:
            not_pqc += 1

    return {
        "pqc_ready": pqc_ready,
        "upgrade_required": upgrade_required,
        "not_pqc": not_pqc
    }


# =====================================================
# OPTIONAL: LIST PQC DETAILS PER ASSET
# =====================================================

@router.get("/pqc/assets")
def get_pqc_assets(db: Session = Depends(get_db)):
    """
    Returns asset-level PQC readiness information
    """

    assets = db.query(AssetRegistry).all()

    result = []

    for a in assets:

        result.append({
            "asset_id": getattr(a, "id", None),
            "domain": getattr(a, "domain", None),
            "ip": getattr(a, "ip", None),
            "pqc_status": getattr(a, "pqc_status", "unknown")
        })

    return result