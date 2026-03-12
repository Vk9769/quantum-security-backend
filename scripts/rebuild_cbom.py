from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate
from app.services.pqc_service import store_cbom


db: Session = SessionLocal()

assets = db.query(AssetRegistry).all()

for asset in assets:

    tls = db.query(TLSScanResult).filter(
        TLSScanResult.asset_id == asset.id
    ).order_by(TLSScanResult.scan_time.desc()).first()

    cert = db.query(Certificate).filter(
        Certificate.asset_id == asset.id
    ).order_by(Certificate.expiry_date.desc()).first()

    store_cbom(
        db,
        asset_hostname=asset.asset_identifier,
        tls_version=tls.tls_version if tls else None,
        cipher_suite=tls.cipher_suite if tls else None,
        key_exchange=tls.key_exchange if tls else None,
        certificate_id=cert.id if cert else None
    )

print("CBOM rebuild complete")