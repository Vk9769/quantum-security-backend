from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.postgres import get_db
from app.models.asset_registry import AssetRegistry

from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.cbom import CBOMInventory
from app.models.pqc import PQCAnalysis
from app.models.scan import PortScanResult
from tldextract import extract

router = APIRouter()


# ---------------------------------------------------
# Get All Assets
# ---------------------------------------------------

@router.get("/assets")
def get_assets(db: Session = Depends(get_db)):

    assets = db.query(AssetRegistry).all()

    result = []

    for a in assets:

        # extract root domain
        ext = extract(a.asset_identifier)
        domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else a.asset_identifier
        
        port_scan = db.query(PortScanResult).filter(
            PortScanResult.asset_id == a.id
        ).first()

        # get tls scan
        tls = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == a.id
        ).first()

        # get cbom crypto
        cbom = db.query(CBOMInventory).filter(
            CBOMInventory.asset_id == a.id
        ).first()

        # get pqc analysis
        pqc = db.query(PQCAnalysis).filter(
            PQCAnalysis.asset_id == a.id
        ).first()

        result.append({
            "id": str(a.id),
            "name": a.asset_identifier,
            "type": a.asset_type,
            "domain": domain,
            "ip": "-",
           "port": port_scan.port if port_scan else "-",
            "tls": tls.tls_version if tls else "-",
            "pqc": "PQC" if pqc and pqc.pqc_ready else "Upgrade"
        })

    return result


# ---------------------------------------------------
# Assets Summary (for dashboard cards)
# ---------------------------------------------------

@router.get("/assets/summary")
def get_assets_summary(db: Session = Depends(get_db)):

    total_assets = db.query(AssetRegistry).count()

    return [
        {
            "label": "Total Assets",
            "value": str(total_assets),
            "change": "+0%",
            "icon": "Server",
            "positive": True
        },
        {
            "label": "New Issues",
            "value": "0",
            "change": "+0%",
            "icon": "AlertTriangle",
            "positive": False
        },
        {
            "label": "Resolved Issues",
            "value": "0",
            "change": "+0%",
            "icon": "CheckCircle",
            "positive": True
        },
        {
            "label": "Ignored Issues",
            "value": "0",
            "change": "+0%",
            "icon": "XCircle",
            "positive": False
        }
    ]